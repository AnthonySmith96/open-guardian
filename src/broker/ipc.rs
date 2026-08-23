//! Broker daemon: loopback-only HTTP IPC with two bearer roles.
//!
//! - **Agent token** (used by the MCP server): list actions, create requests,
//!   poll status. It can never see an approval code or approve anything.
//! - **Admin token** (operator CLI): approve/deny/list. The only channel that
//!   ever sees pending approval codes.
//!
//! `build_router` returns a plain axum `Router` so tests can drive the exact
//! production daemon in-process, mirroring the egress proxy's `build_router`.

use super::execute::execute_action;
use super::policy::{ActionDef, Policy};
use super::state::{constant_time_eq, ApproveError, RequestStore};
use crate::security::{AuditChain, DlpEngine};
use axum::{
    extract::{Json, State as AxumState},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use chrono::Utc;
use open_guardian::secrets::SecretBroker;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub const AGENT_DISCOVERY_FILE: &str = "guardian-broker.json";
pub const ADMIN_DISCOVERY_FILE: &str = "guardian-broker-admin.json";

#[derive(Clone)]
pub struct DaemonOptions {
    pub policy: Policy,
    pub secret_broker: Arc<SecretBroker>,
    pub dlp_engine: Arc<DlpEngine>,
    pub audit: Arc<AuditChain>,
    pub store: Arc<RequestStore>,
    pub agent_token: String,
    pub admin_token: String,
}

impl DaemonOptions {
    /// Convenience constructor: generates both bearer tokens and the store
    /// with the given TTLs.
    pub fn new(
        policy: Policy,
        secret_broker: Arc<SecretBroker>,
        dlp_engine: Arc<DlpEngine>,
        audit: Arc<AuditChain>,
        pending_ttl: Duration,
        result_ttl: Duration,
    ) -> Self {
        Self {
            policy,
            secret_broker,
            dlp_engine,
            audit,
            store: Arc::new(RequestStore::new(pending_ttl, result_ttl)),
            agent_token: random_token(),
            admin_token: random_token(),
        }
    }
}

fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub struct Shared {
    policy: Policy,
    secret_broker: Arc<SecretBroker>,
    dlp: Arc<DlpEngine>,
    audit: Arc<AuditChain>,
    store: Arc<RequestStore>,
    agent_token: String,
    admin_token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Agent,
    Admin,
}

fn audit_event(name: &str, fields: Value) -> Value {
    let mut event = fields;
    if let Some(object) = event.as_object_mut() {
        object.insert("timestamp".into(), Value::String(Utc::now().to_rfc3339()));
        // Keep `event` adjacent to `timestamp` for readability; serde_json's
        // key-sorted map makes the final layout deterministic anyway.
        object.insert("event".into(), Value::String(name.to_string()));
    }
    event
}

fn role_of(headers: &HeaderMap, shared: &Shared) -> Option<Role> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let token = header.strip_prefix("Bearer ")?;
    if constant_time_eq(token.as_bytes(), shared.admin_token.as_bytes()) {
        Some(Role::Admin)
    } else if constant_time_eq(token.as_bytes(), shared.agent_token.as_bytes()) {
        Some(Role::Agent)
    } else {
        None
    }
}

fn unauthorized() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        "{\"error\":\"unauthorized\"}\n",
    )
        .into_response()
}

fn forbidden_agent() -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        "{\"error\":\"admin_channel_required\"}\n",
    )
        .into_response()
}

fn json_response(status: StatusCode, body: Value) -> axum::response::Response {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_default() + "\n",
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestIn {
    action_id: String,
    #[serde(default)]
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveIn {
    request_id: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    yes: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DenyIn {
    request_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusIn {
    request_id: String,
}

async fn list_actions(
    AxumState(shared): AxumState<Arc<Shared>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if role_of(&headers, &shared).is_none() {
        return unauthorized();
    }
    let actions: Vec<Value> = shared
        .policy
        .actions
        .iter()
        .map(|action| {
            json!({
                "id": action.id,
                "description": action.description,
                "requires_elevation": action.user.is_some(),
            })
        })
        .collect();
    json_response(StatusCode::OK, json!({ "actions": actions }))
}

async fn create_request(
    AxumState(shared): AxumState<Arc<Shared>>,
    headers: HeaderMap,
    Json(input): Json<RequestIn>,
) -> axum::response::Response {
    if role_of(&headers, &shared).is_none() {
        return unauthorized();
    }
    let Some(action) = shared.policy.action(&input.action_id) else {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"error": "unknown_action", "action_id": input.action_id}),
        );
    };
    if action.id != input.action_id {
        return json_response(StatusCode::NOT_FOUND, json!({"error": "unknown_action"}));
    }

    // The agent-supplied reason is free text: sanitize before storing or
    // echoing anywhere, exactly like any other inbound string.
    let reason: String = shared
        .dlp
        .redact_permanent(&input.reason)
        .chars()
        .take(500)
        .collect();

    let created = shared.store.create(&action.id, &reason);
    shared.audit.log(audit_event(
        "action_requested",
        json!({
            "request_id": created.record.id,
            "action_id": action.id,
            "reason": reason,
        }),
    ));
    notify_pending(&action.id, &created.record.id, &created.code, &reason);

    json_response(
        StatusCode::OK,
        json!({
            "request_id": created.record.id,
            "status": "pending",
            "expires_in_secs": created.pending_ttl.as_secs(),
            "message": "awaiting operator approval (out-of-band)",
        }),
    )
}

fn notify_pending(action_id: &str, request_id: &str, code: &str, reason: &str) {
    let reason_display = if reason.is_empty() {
        "no reason given"
    } else {
        reason
    };
    let line = format!(
        "BROKER pending: '{action_id}' ({reason_display}) — approve: open-guardian approve {request_id} --code {code}"
    );
    println!("{line}");
    #[cfg(all(unix, feature = "desktop-notify"))]
    {
        let _ = notify_rust::Notification::new()
            .summary("Open-Guardian: action requested")
            .body(&line)
            .show();
    }
}

async fn approve_request(
    AxumState(shared): AxumState<Arc<Shared>>,
    headers: HeaderMap,
    Json(input): Json<ApproveIn>,
) -> axum::response::Response {
    if role_of(&headers, &shared) != Some(Role::Admin) {
        return if role_of(&headers, &shared).is_some() {
            forbidden_agent()
        } else {
            unauthorized()
        };
    }

    let expected_code = shared.store.code_of(&input.request_id);
    if !input.yes {
        let Some(expected) = expected_code.as_ref() else {
            return json_response(
                StatusCode::CONFLICT,
                json!({"error": "not_pending", "message": "request is not awaiting approval"}),
            );
        };
        let provided = input.code.as_deref().unwrap_or("");
        if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
            shared.audit.log(audit_event(
                "action_approve_rejected",
                json!({"request_id": input.request_id, "reason": "wrong_code"}),
            ));
            return json_response(
                StatusCode::FORBIDDEN,
                json!({"error": "wrong_code", "message": "run `open-guardian requests` to see the code"}),
            );
        }
    }

    match shared
        .store
        .approve(&input.request_id, expected_code.as_deref().unwrap_or(""))
    {
        Ok(approved) => {
            shared.audit.log(audit_event(
                "action_approved",
                json!({
                    "request_id": input.request_id,
                    "action_id": approved.action_id,
                    "code_bypassed": input.yes,
                }),
            ));

            // Execute with the exact policy definition — never trusting any
            // argv that arrived over IPC.
            let action: ActionDef = shared
                .policy
                .action(&approved.action_id)
                .expect("approved action exists in the signed policy")
                .clone();
            let execution_shared = shared.clone();
            let request_id = input.request_id.clone();
            tokio::spawn(async move {
                let result = execute_action(
                    &action,
                    &execution_shared.secret_broker,
                    &execution_shared.dlp,
                )
                .await;
                execution_shared.audit.log(audit_event(
                    "action_executed",
                    json!({
                        "request_id": request_id,
                        "action_id": action.id,
                        "exit_code": result.exit_code,
                        "duration_ms": result.duration_ms,
                        "truncated": result.truncated,
                        "suppressed": result.suppressed,
                        "error": result.error,
                    }),
                ));
                execution_shared.store.complete(&request_id, result);
            });

            json_response(
                StatusCode::OK,
                json!({
                    "request_id": input.request_id,
                    "status": "executing",
                    "message": "approved; execution started. Poll /v1/status for the one-time result.",
                }),
            )
        }
        Err(ApproveError::Unknown) => {
            json_response(StatusCode::NOT_FOUND, json!({"error": "unknown_request"}))
        }
        Err(ApproveError::NotPending(why)) => json_response(
            StatusCode::CONFLICT,
            json!({"error": "not_pending", "message": why}),
        ),
        Err(ApproveError::WrongCode) => {
            json_response(StatusCode::FORBIDDEN, json!({"error": "wrong_code"}))
        }
    }
}

async fn deny_request(
    AxumState(shared): AxumState<Arc<Shared>>,
    headers: HeaderMap,
    Json(input): Json<DenyIn>,
) -> axum::response::Response {
    if role_of(&headers, &shared) != Some(Role::Admin) {
        return if role_of(&headers, &shared).is_some() {
            forbidden_agent()
        } else {
            unauthorized()
        };
    }
    match shared.store.deny(&input.request_id) {
        Ok(()) => {
            shared.audit.log(audit_event(
                "action_denied",
                json!({"request_id": input.request_id}),
            ));
            json_response(StatusCode::OK, json!({"status": "denied"}))
        }
        Err(ApproveError::Unknown) => {
            json_response(StatusCode::NOT_FOUND, json!({"error": "unknown_request"}))
        }
        Err(ApproveError::NotPending(why)) => json_response(
            StatusCode::CONFLICT,
            json!({"error": "not_pending", "message": why}),
        ),
        Err(ApproveError::WrongCode) => unreachable!("deny never checks codes"),
    }
}

async fn request_status(
    AxumState(shared): AxumState<Arc<Shared>>,
    headers: HeaderMap,
    Json(input): Json<StatusIn>,
) -> axum::response::Response {
    let Some(role) = role_of(&headers, &shared) else {
        return unauthorized();
    };
    let Some(record) = shared.store.snapshot(&input.request_id) else {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({"error": "unknown_request", "status": "unknown"}),
        );
    };

    let status = record.state.name();
    let mut body = json!({
        "request_id": record.id,
        "action_id": record.action_id,
        "reason": record.reason,
        "status": status,
        "created_at": record.created_at.to_rfc3339(),
    });

    // One-time result delivery (Vault single-reader semantics): whoever
    // reads first consumes it; later readers see a tombstone note.
    let delivered = shared.store.deliver(&input.request_id);
    if let Some(result) = delivered {
        if let Some(object) = body.as_object_mut() {
            object.insert("result".into(), result.to_json());
        }
        shared.audit.log(audit_event(
            "result_delivered",
            json!({
                "request_id": record.id,
                "action_id": record.action_id,
                "channel": if role == Role::Admin { "admin" } else { "agent" },
            }),
        ));
    } else if status == "completed" {
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "note".into(),
                Value::String("result already delivered once".into()),
            );
        }
    }

    json_response(StatusCode::OK, body)
}

async fn list_requests(
    AxumState(shared): AxumState<Arc<Shared>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if role_of(&headers, &shared) != Some(Role::Admin) {
        return if role_of(&headers, &shared).is_some() {
            forbidden_agent()
        } else {
            unauthorized()
        };
    }
    let requests: Vec<Value> = shared
        .store
        .list()
        .into_iter()
        .map(|record| {
            let mut entry = json!({
                "id": record.id,
                "action_id": record.action_id,
                "reason": record.reason,
                "status": record.state.name(),
                "created_at": record.created_at.to_rfc3339(),
            });
            // The approval code is shown ONLY here and only while pending:
            // this endpoint is reachable with the admin token alone.
            if let super::state::RequestState::Pending { code, .. } = &record.state {
                entry["code"] = Value::String(code.clone());
            }
            entry
        })
        .collect();
    json_response(StatusCode::OK, json!({ "requests": requests }))
}

/// Assembles the daemon router. Serve it on 127.0.0.1 only.
pub fn build_router(options: DaemonOptions) -> Router {
    let DaemonOptions {
        policy,
        secret_broker,
        dlp_engine,
        audit,
        store,
        agent_token,
        admin_token,
    } = options;

    let shared = Arc::new(Shared {
        policy,
        secret_broker,
        dlp: dlp_engine,
        audit,
        store,
        agent_token,
        admin_token,
    });

    Router::new()
        .route("/v1/actions", post(list_actions))
        .route("/v1/request", post(create_request))
        .route("/v1/status", post(request_status))
        .route("/v1/approve", post(approve_request))
        .route("/v1/deny", post(deny_request))
        .route("/v1/requests", post(list_requests))
        .with_state(shared)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Discovery files
// ─────────────────────────────────────────────────────────────────────────────

/// Directory holding the discovery files (addr + bearer tokens).
pub fn runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("GUARDIAN_BROKER_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    std::env::temp_dir().join("guardian-broker")
}

fn write_discovery(path: &std::path::Path, addr: SocketAddr, token: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("cannot create {}: {error}", parent.display()))?;
    }
    let body = json!({"addr": addr.to_string(), "token": token});
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| anyhow::anyhow!("cannot write {}: {error}", path.display()))?;
        file.write_all((serde_json::to_string_pretty(&body).unwrap() + "\n").as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, serde_json::to_string_pretty(&body).unwrap() + "\n")?;
    Ok(())
}

/// Reads a discovery file written by a running daemon.
pub fn read_discovery(file: &str) -> anyhow::Result<(String, String)> {
    let path = runtime_dir().join(file);
    let content = std::fs::read_to_string(&path).map_err(|error| {
        anyhow::anyhow!(
            "cannot read {} (is the broker running?): {error}",
            path.display()
        )
    })?;
    let value: Value = serde_json::from_str(&content)
        .map_err(|error| anyhow::anyhow!("malformed discovery file {}: {error}", path.display()))?;
    let addr = value
        .get("addr")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("discovery file missing addr"))?
        .to_string();
    let token = value
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("discovery file missing token"))?
        .to_string();
    Ok((addr, token))
}

/// Binds loopback, writes both discovery files, spawns the sweeper, and
/// serves until the shutdown token fires. Returns the bound address.
pub async fn start(
    options: DaemonOptions,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> anyhow::Result<SocketAddr> {
    options.audit.log(audit_event(
        "policy_loaded",
        json!({
            "fingerprint": options.policy.fingerprint,
            "actions": options.policy.actions.len(),
        }),
    ));

    let agent_token = options.agent_token.clone();
    let admin_token = options.admin_token.clone();
    let store = options.store.clone();
    let audit = options.audit.clone();
    let action_count = options.policy.actions.len();
    let router = build_router(options);

    // Loopback only, ephemeral port: never exposed to the network.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let dir = runtime_dir();
    write_discovery(&dir.join(AGENT_DISCOVERY_FILE), addr, &agent_token)?;
    write_discovery(&dir.join(ADMIN_DISCOVERY_FILE), addr, &admin_token)?;

    audit.log(audit_event(
        "broker_started",
        json!({"addr": addr.to_string(), "actions": action_count}),
    ));

    // Sweeper: expire stale pending requests and drop consumed results.
    let sweeper_audit = audit.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            for request_id in store.sweep() {
                sweeper_audit.log(audit_event(
                    "action_expired",
                    json!({"request_id": request_id}),
                ));
            }
        }
    });

    println!(
        "BROKER listening on {addr} ({action_count} actions). Agent file: {} | Admin file: {}",
        dir.join(AGENT_DISCOVERY_FILE).display(),
        dir.join(ADMIN_DISCOVERY_FILE).display()
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            shutdown_token.cancelled().await;
            println!("BROKER shutting down.");
        })
        .await?;

    audit.log(audit_event("broker_stopped", json!({})));
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::policy::{EnvBinding, OutputPolicy};
    use crate::config::DlpConfig;
    use crate::security::DlpEngine;
    use async_trait::async_trait;
    use open_guardian::secrets::{SecretBackend, SecretBroker, SecretRef, SecretValue};

    const AGENT_TOKEN: &str = "agent-test-token";
    const ADMIN_TOKEN: &str = "admin-test-token";
    const SECRET: &str = "sk_live_Qw3Er5Ty7Ui9Op1As3DfGh";

    struct FixedBackend;

    #[async_trait]
    impl SecretBackend for FixedBackend {
        fn scheme(&self) -> &'static str {
            "test"
        }
        async fn resolve(
            &self,
            _reference: &SecretRef,
        ) -> Result<SecretValue, open_guardian::secrets::SecretError> {
            SecretValue::new(SECRET.to_string())
        }
    }

    fn echo_action() -> ActionDef {
        ActionDef {
            id: "echo-token".into(),
            description: "Echo the deploy token (DLP must redact it)".into(),
            exec: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf 'deploy used token=%s\\n' \"$DEPLOY_TOKEN\"".into(),
            ],
            user: None,
            timeout_secs: 10,
            output: OutputPolicy::Redact,
            env: vec![EnvBinding {
                name: "DEPLOY_TOKEN".into(),
                reference: "{{secret:test://prod/deploy#token}}".parse().expect("ref"),
            }],
        }
    }

    struct TestDaemon {
        base: String,
        audit_path: std::path::PathBuf,
        _server: tokio::task::JoinHandle<()>,
        _writer: tokio::task::JoinHandle<()>,
    }

    impl TestDaemon {
        async fn start() -> Self {
            let policy = Policy {
                actions: vec![echo_action()],
                fingerprint: "testfingerprint".into(),
            };
            let mut secret_broker = SecretBroker::new();
            secret_broker.register(FixedBackend).expect("register");
            let dlp = DlpEngine::build(&DlpConfig::default()).expect("dlp engine");

            // Unique per daemon instance: tests run concurrently in-process.
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let instance = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let audit_path = std::env::temp_dir().join(format!(
                "guardian-broker-ipc-{}-{instance}.jsonl",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&audit_path);
            let (audit, writer) = AuditChain::open(&audit_path).expect("audit chain");

            let options = DaemonOptions {
                policy,
                secret_broker: Arc::new(secret_broker),
                dlp_engine: Arc::new(dlp),
                audit,
                store: Arc::new(RequestStore::new(
                    Duration::from_secs(120),
                    Duration::from_secs(300),
                )),
                agent_token: AGENT_TOKEN.into(),
                admin_token: ADMIN_TOKEN.into(),
            };
            let router = build_router(options);

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let server = tokio::spawn(async move {
                axum::serve(listener, router).await.expect("daemon serve");
            });

            Self {
                base: format!("http://{addr}"),
                audit_path,
                _server: server,
                _writer: writer,
            }
        }

        async fn post(&self, path: &str, token: &str, body: Value) -> (u16, Value) {
            let client = reqwest::Client::new();
            let response = client
                .post(format!("{}{path}", self.base))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .expect("request");
            let status = response.status().as_u16();
            let payload = response.json().await.expect("json");
            (status, payload)
        }

        fn audit_content(&self) -> String {
            std::fs::read_to_string(&self.audit_path).expect("audit file")
        }
    }

    #[tokio::test]
    async fn full_lifecycle_approve_execute_and_one_time_delivery() {
        let daemon = TestDaemon::start().await;

        // Agent requests the action with a reason containing PII: the stored
        // reason must come back redacted.
        let (status, body) = daemon
            .post(
                "/v1/request",
                AGENT_TOKEN,
                json!({"action_id": "echo-token", "reason": "deploy for bob@example.com"}),
            )
            .await;
        assert_eq!(status, 200, "body: {body}");
        let request_id = body["request_id"].as_str().expect("id").to_string();
        assert_eq!(body["status"], "pending");
        assert!(
            !body.to_string().contains("example.com"),
            "agent response echoed unredacted reason: {body}"
        );

        // Agent cannot approve, even with the right code (unknown to it).
        let (status, body) = daemon
            .post(
                "/v1/approve",
                AGENT_TOKEN,
                json!({"request_id": request_id, "code": "whatever"}),
            )
            .await;
        assert_eq!(status, 403, "agent channel must not approve: {body}");
        assert_eq!(body["error"], "admin_channel_required");

        // Admin listing shows the code.
        let (status, body) = daemon.post("/v1/requests", ADMIN_TOKEN, Value::Null).await;
        assert_eq!(status, 200);
        let listing = body["requests"].as_array().expect("requests");
        let code = listing[0]["code"]
            .as_str()
            .expect("pending code")
            .to_string();
        assert_eq!(code.len(), 6);

        // Wrong code is rejected and audited.
        let (status, _) = daemon
            .post(
                "/v1/approve",
                ADMIN_TOKEN,
                json!({"request_id": request_id, "code": "wrong1"}),
            )
            .await;
        assert_eq!(status, 403);

        // Correct code approves; execution runs.
        let (status, body) = daemon
            .post(
                "/v1/approve",
                ADMIN_TOKEN,
                json!({"request_id": request_id, "code": code}),
            )
            .await;
        assert_eq!(status, 200, "body: {body}");

        // Poll until completed; the secret injected into the child env must
        // never appear in the delivered result.
        let mut delivered = None;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let (status, body) = daemon
                .post("/v1/status", AGENT_TOKEN, json!({"request_id": request_id}))
                .await;
            assert_eq!(status, 200);
            if body["status"] == "completed" {
                if body.get("result").is_some() {
                    delivered = Some(body);
                    break;
                }
                delivered = Some(body); // already consumed elsewhere
                break;
            }
        }
        let delivered = delivered.expect("request completed");
        let result = delivered.get("result").expect("one-time result");
        assert!(
            !result.to_string().contains(SECRET),
            "result leaked the secret: {result}"
        );
        assert!(result["stdout"]
            .as_str()
            .expect("stdout")
            .contains("token="));

        // Second poll: no result again (single delivery).
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (status, body) = daemon
            .post("/v1/status", AGENT_TOKEN, json!({"request_id": request_id}))
            .await;
        assert_eq!(status, 200);
        assert!(
            body.get("result").is_none(),
            "result delivered twice: {body}"
        );

        // The whole story is in the audit chain — and the chain verifies.
        let audit = daemon.audit_content();
        assert!(audit.contains("action_requested"));
        assert!(audit.contains("action_approve_rejected"));
        assert!(audit.contains("action_approved"));
        assert!(audit.contains("action_executed"));
        assert!(audit.contains("result_delivered"));
        assert!(!audit.contains(SECRET), "audit leaked the secret");
        assert!(!audit.contains("example.com"), "audit leaked reason PII");
        let report =
            crate::security::verify_audit_chain(&daemon.audit_path).expect("chain verifies");
        assert!(report.lines >= 5);
    }

    #[tokio::test]
    async fn unknown_action_is_rejected_and_denial_is_audited() {
        let daemon = TestDaemon::start().await;

        let (status, _) = daemon
            .post(
                "/v1/request",
                AGENT_TOKEN,
                json!({"action_id": "definitely-not-in-policy", "reason": "x"}),
            )
            .await;
        assert_eq!(status, 404);

        // Valid request, then denied by the operator.
        let (_, body) = daemon
            .post(
                "/v1/request",
                AGENT_TOKEN,
                json!({"action_id": "echo-token", "reason": "test"}),
            )
            .await;
        let request_id = body["request_id"].as_str().expect("id").to_string();

        let (status, body) = daemon
            .post("/v1/deny", ADMIN_TOKEN, json!({"request_id": request_id}))
            .await;
        assert_eq!(status, 200, "{body}");

        let (status, body) = daemon
            .post("/v1/status", AGENT_TOKEN, json!({"request_id": request_id}))
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["status"], "denied");

        assert!(daemon.audit_content().contains("action_denied"));
    }

    #[tokio::test]
    async fn bad_tokens_and_agent_listing_are_rejected() {
        let daemon = TestDaemon::start().await;

        let (status, _) = daemon
            .post(
                "/v1/request",
                "wrong-token",
                json!({"action_id": "echo-token", "reason": "x"}),
            )
            .await;
        assert_eq!(status, 401);

        // The agent channel must never see approval codes.
        let (status, body) = daemon.post("/v1/requests", AGENT_TOKEN, Value::Null).await;
        assert_eq!(status, 403, "{body}");
    }

    #[tokio::test]
    async fn list_actions_shows_policy_surface() {
        let daemon = TestDaemon::start().await;
        let (status, body) = daemon.post("/v1/actions", AGENT_TOKEN, Value::Null).await;
        assert_eq!(status, 200);
        let actions = body["actions"].as_array().expect("actions");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["id"], "echo-token");
        assert_eq!(actions[0]["requires_elevation"], false);
    }
}
