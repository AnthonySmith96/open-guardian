use crate::banner;
use crate::config::{DlpConfig, RouteConfig, SecurityConfig, VaultConfig};
use crate::pipeline::{extract_scan_targets, replace_scan_target};
use crate::proxy::ProxyClient;
use crate::security::{
    normalize_for_matching, DlpAction, DlpEngine, PerIpRateLimiter, RedactionSession,
    DEFAULT_REQUESTS_PER_MINUTE,
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use chrono::Utc;
use colored::Colorize;
#[cfg(feature = "native-keyring")]
use open_guardian::secrets::KeychainBackend;
#[cfg(feature = "portable-vault")]
use open_guardian::secrets::PortableVaultBackend;
use open_guardian::secrets::{EnvironmentBackend, SecretBroker};
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct ServerConfig {
    pub bind_address: String,
    pub port: u16,
    pub default_upstream: String,
    pub routes: HashMap<String, RouteConfig>,
    pub audit_log_path: Option<String>,
    pub requests_per_minute: Option<u32>,
    pub timeout_seconds: u64,
    pub verbose: bool,
    pub dlp_config: DlpConfig,
    /// Optional Semantic Load Balancer config.
    pub load_balancer: Option<crate::config::LoadBalancerConfig>,
    /// Security configuration for hardening options.
    pub security: Option<SecurityConfig>,
    pub vault: Option<VaultConfig>,
}

#[derive(Clone)]
struct AppState {
    proxy: Arc<ProxyClient>,
    dlp_engine: Arc<DlpEngine>,
    dlp_action: DlpAction,
    /// `None` disables rate limiting (requests_per_minute = 0).
    rate_limiter: Option<Arc<PerIpRateLimiter>>,
    default_upstream: String,
    routes: HashMap<String, RouteConfig>,
    audit_log_path: Option<String>,
    verbose: bool,
    /// Semantic Load Balancer config (None = disabled).
    slb_config: Option<crate::config::LoadBalancerConfig>,
    /// Security config for non-JSON handling and other security policies
    security_config: SecurityConfig,
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK\n")
}

fn get_hmac_key() -> anyhow::Result<Option<String>> {
    match std::env::var("GUARDIAN_HMAC_KEY") {
        Ok(key) if !key.is_empty() => Ok(Some(key)),
        Ok(_) => Err(anyhow::anyhow!("GUARDIAN_HMAC_KEY cannot be empty")),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(anyhow::anyhow!("GUARDIAN_HMAC_KEY is not valid Unicode"))
        }
    }
}

/// Builds the fully wired proxy router: secret broker, DLP engine, rule
/// integrity, rate limiting, and every handler. `start_server` serves it;
/// the benchmark harness drives the same router in-process so it can never
/// drift from production behavior.
pub async fn build_router(config: &ServerConfig) -> anyhow::Result<(Router, usize)> {
    let mut secret_broker = SecretBroker::new();
    secret_broker.register(EnvironmentBackend)?;
    #[cfg(feature = "native-keyring")]
    secret_broker.register(KeychainBackend)?;
    if let Some(vault) = config.vault.as_ref() {
        #[cfg(feature = "portable-vault")]
        {
            let identity = secret_broker
                .resolve(&vault.identity)
                .await
                .map_err(|error| {
                    anyhow::anyhow!("failed to resolve portable vault device identity: {error}")
                })?;
            let backend = PortableVaultBackend::new(&vault.path, identity)?;
            secret_broker.register(backend)?;
            tracing::warn!(
                "SEC: portable vault is read-only and has no rollback anchor in this prototype"
            );
        }
        #[cfg(not(feature = "portable-vault"))]
        {
            let _ = vault;
            return Err(anyhow::anyhow!(
                "guardian.toml configures [vault], but this binary lacks the portable-vault feature"
            ));
        }
    }
    let proxy = ProxyClient::new(config.timeout_seconds, Arc::new(secret_broker))?;

    // ── DLP engine: rule files load or the server refuses to start ──
    let dlp_engine = DlpEngine::build(&config.dlp_config)
        .map_err(|error| anyhow::anyhow!("DLP engine failed to load: {error}"))?;
    let dlp_action = DlpAction::from_str(&config.dlp_config.action);

    // ── Rule File Integrity Verification (opt-in via GUARDIAN_HMAC_KEY) ──
    let rules_dir = config
        .dlp_config
        .rules_files
        .first()
        .and_then(|file| {
            crate::config::resolve_resource_path(file)
                .as_path()
                .parent()
                .map(|p| p.to_path_buf())
        })
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let manifest_exists = rules_dir.join(".manifest.json").is_file();
    if let Some(hmac_key) = get_hmac_key()? {
        let checker = crate::security::integrity::RuleIntegrityChecker::new(&rules_dir, &hmac_key)
            .map_err(|error| anyhow::anyhow!("failed to initialize rule integrity: {error}"))?;
        let result = checker.verify();
        if !result.verified {
            for failure in &result.failed_files {
                banner::print_error(&format!(
                    "Rule integrity: {} ({})",
                    failure.path, failure.reason
                ));
            }
            return Err(anyhow::anyhow!(
                "Security: Rule file integrity verification failed"
            ));
        }
    } else if manifest_exists {
        return Err(anyhow::anyhow!(
            "rules/.manifest.json exists but GUARDIAN_HMAC_KEY is unavailable"
        ));
    } else {
        tracing::warn!(
            "SEC: rule integrity is not configured; run `open-guardian sign` with GUARDIAN_HMAC_KEY to enable it"
        );
    }

    // ── Per-IP rate limiting ──
    let requests_per_minute = config
        .requests_per_minute
        .unwrap_or(DEFAULT_REQUESTS_PER_MINUTE);
    let rate_limiter = (requests_per_minute > 0).then(|| {
        let limiter = Arc::new(PerIpRateLimiter::new(requests_per_minute));
        limiter.spawn_prune_task(Duration::from_secs(300));
        limiter
    });

    let state = AppState {
        proxy: Arc::new(proxy),
        dlp_engine: Arc::new(dlp_engine),
        dlp_action,
        rate_limiter,
        default_upstream: config.default_upstream.clone(),
        routes: config.routes.clone(),
        audit_log_path: config.audit_log_path.clone(),
        verbose: config.verbose,
        slb_config: config.load_balancer.clone(),
        security_config: config.security.clone().unwrap_or_default(),
    };

    let rule_count = state.dlp_engine.rule_count();

    Ok((
        Router::new()
            .route("/health", any(health_handler))
            .route("/*path", any(handler))
            .with_state(state),
        rule_count,
    ))
}

pub async fn start_server(
    config: ServerConfig,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    let bind_ip = config.bind_address.parse().map_err(|error| {
        anyhow::anyhow!(
            "invalid server.bind_address '{}': {}",
            config.bind_address,
            error
        )
    })?;
    let addr = SocketAddr::new(bind_ip, config.port);

    let (app, rule_count) = build_router(&config).await?;

    banner::print_startup_info(
        &addr.to_string(),
        &config.default_upstream,
        &format!("{:?}", DlpAction::from_str(&config.dlp_config.action)),
        rule_count,
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("Server listening on {}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_token.cancelled().await;
        banner::print_success("Shutdown signal received. Closing server...");
        tracing::info!("Server shutting down gracefully");
    })
    .await?;

    Ok(())
}

fn log_security_event(path: Option<String>, event: Value) {
    tokio::spawn(async move {
        if let Some(log_path) = path {
            if let Ok(line) = serde_json::to_string(&event) {
                use tokio::io::AsyncWriteExt;
                if let Ok(mut file) = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path)
                    .await
                {
                    let _ = file.write_all(format!("{line}\n").as_bytes()).await;
                }
            }
        }
    });
}

/// Build the 403 Forbidden response for policy violations.
fn block_response(category: &str, detail: &str, message: &str) -> Response {
    let error_msg = serde_json::json!({
        "error": "policy_violation",
        "category": category,
        "details": detail,
        "message": message
    });
    let body = serde_json::to_string(&error_msg).unwrap_or_default() + "\n";
    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

fn proxy_error_response() -> Response {
    let error_msg = serde_json::json!({
        "error": "proxy_internal_error",
        "message": "Internal proxy failure"
    });
    let body = serde_json::to_string(&error_msg).unwrap_or_default() + "\n";
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

fn contains_proxy_path_traversal(path: &str) -> bool {
    let lowercase = path.to_ascii_lowercase();
    path.contains('\0')
        || path.contains('\\')
        || path.contains("//")
        || path.split('/').any(|segment| segment == "..")
        || lowercase.contains("%2e%2e")
        || lowercase.contains("%2e%2f")
        || lowercase.contains("%2f%2e")
}

// ================================================================
// THE PIPELINE ORCHESTRATOR — egress data protection
// ================================================================
// 1.  Transport hygiene: smuggling header check + path traversal
// 2.  Per-IP rate limit (token bucket)
// 3.  DLP on every extracted string:
//       a. raw detection (rules + PII) → block mode rejects here
//       b. reversible redaction of what can be located in place
//       c. normalized probe → obfuscated secrets fail closed
// 4.  Model routing (alias table or SLB) + credential injection
// 5.  Response-side DLP + local placeholder restoration (proxy.rs)
// ================================================================
async fn handler(
    State(state): State<AppState>,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    method: Method,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let global_start = std::time::Instant::now();
    let path_str = format!("/{path}");
    tracing::info!("{} request to {}", method, path_str);

    if state.verbose {
        println!("{} {} {}", "INCOMING:".bright_black(), method, path_str);
    }

    // ── Request Smuggling Prevention ──
    let smuggling_config = crate::security::smuggling::SmugglingProtectionConfig::default();
    let header_result = crate::security::smuggling::check_request_headers(
        &headers,
        method.as_str(),
        &smuggling_config,
    );
    if header_result.blocked {
        let block_reason = header_result
            .reason
            .unwrap_or_else(|| "Unknown smuggling attempt".to_string());
        banner::print_warning(&format!("Request smuggling attempt: {block_reason}"));
        log_security_event(
            state.audit_log_path.clone(),
            serde_json::json!({
                "timestamp": Utc::now().to_rfc3339(),
                "event": "smuggling_blocked",
                "reason": block_reason
            }),
        );
        return block_response(
            "Security",
            "request_smuggling",
            "Malformed request headers detected",
        );
    }

    // ── Path Security ──
    // API prefixes do not exempt traversal. The path is forwarded to another
    // HTTP service, so filesystem canonicalization is neither needed nor safe.
    if contains_proxy_path_traversal(&path_str) {
        banner::print_warning("Path traversal blocked");
        log_security_event(
            state.audit_log_path.clone(),
            serde_json::json!({
                "timestamp": Utc::now().to_rfc3339(),
                "event": "path_traversal_blocked",
                "path": path_str
            }),
        );
        return block_response("Security", "path_traversal", "Invalid request path");
    }

    // ── Per-IP Rate Limiting ──
    if let Some(limiter) = &state.rate_limiter {
        if !limiter.check(connect_info.ip()).await {
            banner::print_warning(&format!("Rate limit exceeded for {}", connect_info.ip()));
            log_security_event(
                state.audit_log_path.clone(),
                serde_json::json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "event": "rate_limited",
                    "client_ip": connect_info.ip().to_string()
                }),
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                "{\"error\": \"rate_limit_exceeded\"}\n",
            )
                .into_response();
        }
    }

    // ── Parse JSON body ──
    if let Ok(mut json_body) = serde_json::from_slice::<Value>(&body) {
        let mut redaction_session = RedactionSession::new();
        let model_alias = json_body
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or("default")
            .to_string();
        let route = state.routes.get(&model_alias);

        // Rewrite model if a real model name is provided in the config
        if let Some(r) = route {
            if let Some(real_model) = &r.model {
                if let Some(m_val) = json_body.get_mut("model") {
                    tracing::info!(
                        "Rewriting model alias '{}' to '{}'",
                        model_alias,
                        real_model
                    );
                    *m_val = serde_json::Value::String(real_model.clone());
                }
            }
        }

        let mut upstream_url = route
            .map(|r| r.url.clone())
            .unwrap_or_else(|| state.default_upstream.clone());
        // The SLB may replace this opaque reference when it changes provider.
        let mut effective_credential = route.and_then(|route| route.credential.clone());

        // Accumulates message content for SLB scoring — populated during the
        // scan loop below (reuse already-parsed text, never re-read the stream).
        let mut content_for_slb = String::new();

        let scan_targets = extract_scan_targets(&json_body);
        for target in scan_targets {
            let content_text = target.raw.clone();

            if content_text.is_empty() {
                continue;
            }

            // Accumulate for SLB scoring (safe — already extracted from parsed JSON).
            content_for_slb.push_str(&content_text);
            content_for_slb.push(' ');

            // ════════════════════════════════════════════════════
            // DLP: raw detection → reversible redaction
            // ════════════════════════════════════════════════════
            let dlp_start = std::time::Instant::now();

            if state.dlp_action == DlpAction::Block {
                if let Some(violation) = state.dlp_engine.check_violations(&content_text) {
                    banner::print_warning(&format!(
                        "DLP BLOCKED: {} in {}",
                        violation.description, path_str
                    ));
                    log_security_event(
                        state.audit_log_path.clone(),
                        serde_json::json!({
                            "timestamp": Utc::now().to_rfc3339(),
                            "event": "dlp_blocked",
                            "path": path_str,
                            "category": violation.category,
                            "description": violation.description
                        }),
                    );
                    return block_response(
                        &violation.category,
                        "dlp_violation",
                        &format!("Access Denied: {}", violation.description),
                    );
                }
            }

            let cleaned = redaction_session.redact(&content_text, &state.dlp_engine);
            if state.verbose {
                println!(
                    "   {} DLP scan+redact: {:?}",
                    "DEBUG:".bright_black(),
                    dlp_start.elapsed()
                );
            }

            if cleaned != content_text {
                banner::print_success(&format!("Redacted sensitive data in request to {path_str}"));
                tracing::info!("DLP redaction applied for request to {}", path_str);
                log_security_event(
                    state.audit_log_path.clone(),
                    serde_json::json!({
                        "timestamp": Utc::now().to_rfc3339(),
                        "event": "data_redacted",
                        "path": path_str
                    }),
                );

                if !replace_scan_target(&mut json_body, &target, cleaned.clone()) {
                    tracing::error!(
                        "SECURITY: failed to apply DLP redaction at {}",
                        target.json_pointer
                    );
                    return block_response(
                        "security_policy",
                        "redaction_failed",
                        "Access Denied: sensitive data could not be safely redacted",
                    );
                }
            }

            // ════════════════════════════════════════════════════
            // DLP: obfuscation probe — fail closed
            // ════════════════════════════════════════════════════
            // A secret that only surfaces after NFKC/casefold/URL/HTML
            // decoding cannot be located in the original payload, so it
            // cannot be safely rewritten: reject instead of forwarding.
            if state.dlp_engine.config().block_on_obfuscated {
                let normalized = normalize_for_matching(&cleaned);
                if let Some(violation) = state.dlp_engine.check_violations(&normalized) {
                    banner::print_warning(&format!(
                        "DLP BLOCKED (obfuscated): {} in {}",
                        violation.description, path_str
                    ));
                    log_security_event(
                        state.audit_log_path.clone(),
                        serde_json::json!({
                            "timestamp": Utc::now().to_rfc3339(),
                            "event": "dlp_obfuscated_blocked",
                            "path": path_str,
                            "category": violation.category,
                            "description": violation.description
                        }),
                    );
                    return block_response(
                        &violation.category,
                        "obfuscated_sensitive_data",
                        "Access Denied: sensitive data must not be obfuscated to evade redaction",
                    );
                }
            }
        }

        // ════════════════════════════════════════════════════
        // SEMANTIC LOAD BALANCER (SLB) — Post-Security Routing
        // ════════════════════════════════════════════════════
        // Runs AFTER the DLP pipeline so redaction always fires first.
        if let Some(lb) = &state.slb_config {
            if lb.enabled && !content_for_slb.is_empty() {
                let decision = crate::router::route(&content_for_slb, lb);
                let tier_label = decision.tier.to_string();

                tracing::info!(
                    "SLB routing prompt (Score: {}) -> {} [model: {:?}, url: {}]",
                    decision.score,
                    tier_label,
                    decision.model,
                    decision.upstream_url
                );
                banner::print_step(&format!(
                    "SLB (Score: {}) -> {}",
                    decision.score, tier_label
                ));

                // Hard Override: SLB is authoritative.
                upstream_url = decision.upstream_url;

                // Credential swap is mandatory when the selected provider changes.
                effective_credential = decision.credential;

                // Rewrite model in JSON body if tier specifies one.
                if let Some(ref slb_model) = decision.model {
                    if let Some(m_val) = json_body.get_mut("model") {
                        *m_val = serde_json::Value::String(slb_model.clone());
                    }
                }
            }
        }

        // ════════════════════════════════════════════════════
        // FORWARD
        // ════════════════════════════════════════════════════
        let final_body = match serde_json::to_vec(&json_body) {
            Ok(serialized) => Bytes::from(serialized),
            Err(_) => {
                tracing::error!(
                    "SECURITY: inspected request could not be serialized; refusing original body"
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    "{\"error\":\"request_serialization_failed\"}\n",
                )
                    .into_response();
            }
        };

        banner::print_step(&format!(
            "Forwarding to [{model_alias}] target: {upstream_url}..."
        ));
        let response = match state
            .proxy
            .forward_request(crate::proxy::ForwardOptions {
                upstream_url: &upstream_url,
                credential: effective_credential.as_ref(),
                method,
                path: &path_str,
                headers,
                body: final_body,
                dlp_engine: &state.dlp_engine,
                dlp_action: state.dlp_action,
                redactions: redaction_session,
            })
            .await
        {
            Ok(res) => res,
            Err(e) => {
                banner::print_error(&format!("Internal Proxy Error: {e}"));
                proxy_error_response()
            }
        };

        if state.verbose {
            println!(
                "{} Total processed in {:?}",
                "SHIELD:".bright_green(),
                global_start.elapsed()
            );
        }
        response
    } else {
        // ════════════════════════════════════════════════════
        // Non-JSON Request Handling — default-deny
        // ════════════════════════════════════════════════════
        // If allowed via config, still apply the full raw-text DLP pipeline.
        if !state.security_config.allow_non_json_passthrough {
            banner::print_blocking(&format!(
                "Non-JSON request to {path_str}: BLOCKED (security policy)"
            ));
            tracing::warn!(
                "SECURITY: Non-JSON request blocked. Set allow_non_json_passthrough=true to allow (not recommended)."
            );
            return block_response(
                "security_policy",
                "non_json_not_allowed",
                "Non-JSON requests are blocked by security policy. Please use application/json Content-Type.",
            );
        }

        // Passthrough mode enabled (explicit opt-in, NOT recommended for security)
        banner::print_warning(&format!(
            "Non-JSON passthrough enabled (SECURITY RISK): {path_str}"
        ));
        tracing::warn!(
            "SECURITY: Non-JSON passthrough enabled — JSON-field redaction does not apply!"
        );

        let body_str = match std::str::from_utf8(&body) {
            Ok(body) => body,
            Err(_) => {
                return block_response(
                    "security_policy",
                    "non_json_not_utf8",
                    "Non-JSON request cannot be safely inspected as UTF-8",
                );
            }
        };

        if state.dlp_action == DlpAction::Block {
            if let Some(violation) = state.dlp_engine.check_violations(body_str) {
                banner::print_warning(&format!(
                    "DLP violation detected in non-JSON body to {path_str}"
                ));
                return block_response(
                    &violation.category,
                    "dlp_violation",
                    &format!("Access Denied: {}", violation.description),
                );
            }
        }

        let mut redaction_session = RedactionSession::new();
        let redacted_body = redaction_session.redact(body_str, &state.dlp_engine);

        if state.dlp_engine.config().block_on_obfuscated {
            let normalized = normalize_for_matching(&redacted_body);
            if let Some(violation) = state.dlp_engine.check_violations(&normalized) {
                banner::print_warning(&format!(
                    "DLP BLOCKED (obfuscated) in non-JSON body to {path_str}: {}",
                    violation.description
                ));
                return block_response(
                    &violation.category,
                    "obfuscated_sensitive_data",
                    "Access Denied: sensitive data must not be obfuscated to evade redaction",
                );
            }
        }

        let upstream_url = state.default_upstream.clone();
        let response = match state
            .proxy
            .forward_request(crate::proxy::ForwardOptions {
                upstream_url: &upstream_url,
                credential: None,
                method,
                path: &path_str,
                headers,
                body: Bytes::from(redacted_body),
                dlp_engine: &state.dlp_engine,
                dlp_action: state.dlp_action,
                redactions: redaction_session,
            })
            .await
        {
            Ok(res) => res,
            Err(e) => {
                banner::print_error(&format!("Internal Proxy Error: {e}"));
                proxy_error_response()
            }
        };

        if state.verbose {
            banner::print_warning(&format!(
                "Non-JSON passthrough to {path_str}: SECURITY BYPASSED"
            ));
            println!(
                "{} Total processed (Passthrough) in {:?}",
                "SHIELD:".bright_green(),
                global_start.elapsed()
            );
        }
        response
    }
}

#[cfg(test)]
mod path_tests {
    use super::contains_proxy_path_traversal;

    #[test]
    fn api_prefix_never_exempts_traversal() {
        for path in [
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/api/%2E%2Fadmin",
            "/v1\\..\\admin",
            "/v1//admin",
        ] {
            assert!(contains_proxy_path_traversal(path), "accepted {path}");
        }

        assert!(!contains_proxy_path_traversal("/v1/chat/completions"));
        assert!(!contains_proxy_path_traversal("/api/models/qwen3:8b"));
    }
}
