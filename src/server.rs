use crate::banner;
use crate::config::{JudgeConfig, PolicyAction, PolicyConfig, RouteConfig};
use crate::proxy::ProxyClient;
use crate::security::{
    analyze_injection, check_for_violations, redact_pii, DlpAction, Judge, ThreatEngine,
};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use chrono::Utc;
use colored::Colorize;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct ServerConfig {
    pub port: u16,
    pub default_upstream: String,
    pub routes: HashMap<String, RouteConfig>,
    pub judge_config: JudgeConfig,
    pub audit_log_path: Option<String>,
    pub block_threshold: Option<u32>,
    pub requests_per_minute: Option<u32>,
    pub timeout_seconds: u64,
    pub verbose: bool,
    pub policies: PolicyConfig,
    pub dlp_config: crate::config::DlpConfig,
    /// Optional Semantic Load Balancer config.
    pub load_balancer: Option<crate::config::LoadBalancerConfig>,
    /// Security configuration for hardening options.
    pub security: Option<crate::config::SecurityConfig>,
}

#[derive(Clone)]
struct AppState {
    proxy: Arc<ProxyClient>,
    judge: Arc<Judge>,
    threat_engine: Arc<ThreatEngine>,
    default_upstream: String,
    routes: HashMap<String, RouteConfig>,
    audit_log_path: Option<String>,
    block_threshold: u32,
    #[allow(clippy::type_complexity)]
    rate_limiter: Option<Arc<tokio::sync::Mutex<HashMap<String, (u32, std::time::Instant)>>>>,
    rate_limit_requests_per_minute: u32,
    verbose: bool,
    // Policy settings
    default_action: PolicyAction,
    dlp_action: DlpAction,
    dlp_config: crate::config::DlpConfig,
    /// Semantic Load Balancer config (None = disabled).
    slb_config: Option<crate::config::LoadBalancerConfig>,
    /// Security config for non-JSON handling and other security policies
    security_config: crate::config::SecurityConfig,
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK\n")
}

fn get_hmac_key() -> String {
    match std::env::var("GUARDIAN_HMAC_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            if cfg!(debug_assertions) {
                tracing::warn!("SEC: GUARDIAN_HMAC_KEY not set — using insecure dev key. DO NOT USE IN PRODUCTION.");
                "insecure-dev-only-key".to_string()
            } else {
                panic!("FATAL: GUARDIAN_HMAC_KEY environment variable must be set in release mode");
            }
        }
    }
}

pub async fn start_server(
    config: ServerConfig,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    let proxy = ProxyClient::new(config.timeout_seconds)?;
    let judge = Judge::new(config.judge_config.clone());

    // ── Layer 0: Rule File Integrity Verification ──
    // Verify HMAC integrity of rule files before starting the server
    let rules_dir = config
        .policies
        .dictionaries
        .first()
        .and_then(|d| {
            std::path::Path::new(&d.path)
                .parent()
                .map(|p| p.to_path_buf())
        })
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let integrity_checker = crate::security::integrity::RuleIntegrityChecker::new(
        &rules_dir,
        &get_hmac_key(),
        false, // Emergency kit disabled by default
    );
    if let Ok(checker) = integrity_checker {
        let result = checker.verify();
        if !result.verified {
            banner::print_error(&format!(
                "Rule integrity check failed: {:?}",
                result.failed_files
            ));
            return Err(anyhow::anyhow!(
                "Security: Rule file integrity verification failed"
            ));
        }
    }
    // If integrity checker fails to initialize (e.g., no manifest), continue (optional warning)

    let threat_engine = ThreatEngine::new(
        &config.policies.dictionaries,
        config.policies.allowed_patterns.clone(),
    );

    let default_action = PolicyAction::from_str(&config.policies.default_action);
    let dlp_action = DlpAction::from_str(&config.policies.dlp_action);

    let state = AppState {
        proxy: Arc::new(proxy),
        judge: Arc::new(judge),
        threat_engine: Arc::new(threat_engine),
        default_upstream: config.default_upstream.clone(),
        routes: config.routes,
        audit_log_path: config.audit_log_path.clone(),
        block_threshold: config.block_threshold.unwrap_or(50),
        rate_limiter: Some(Arc::new(tokio::sync::Mutex::new(HashMap::new()))),
        rate_limit_requests_per_minute: config.requests_per_minute.unwrap_or(u32::MAX),
        verbose: config.verbose,
        default_action,
        dlp_action,
        dlp_config: config.dlp_config.clone(),
        slb_config: config.load_balancer,
        security_config: config.security.clone().unwrap_or_default(),
    };

    let app = Router::new()
        .route("/health", any(health_handler))
        .route("/*path", any(handler))
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let model_info = if config.judge_config.ai_judge_enabled.unwrap_or(false) {
        config
            .judge_config
            .ai_judge_model
            .as_ref()
            .unwrap_or(&"qwen3:4b".to_string())
            .clone()
    } else {
        "DISABLED".to_string()
    };

    banner::print_startup_info(
        &addr.to_string(),
        &config.default_upstream,
        &format!("{:?}", default_action),
        &format!("{:?}", dlp_action),
        &model_info,
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("Server listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_token.cancelled().await;
            banner::print_success("Shutdown signal received. Closing server...");
            tracing::info!("Server shutting down gracefully");
        })
        .await?;

    Ok(())
}

fn extract_full_content(content: &Value) -> String {
    if let Some(s) = content.as_str() {
        return s.to_string();
    }

    if let Some(parts) = content.as_array() {
        let mut full_text = String::new();
        for part in parts {
            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                full_text.push_str(text);
                full_text.push(' ');
            }
        }
        return full_text.trim().to_string();
    }

    String::new()
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
                    let _ = file.write_all(format!("{}\n", line).as_bytes()).await;
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

// ================================================================
// THE PIPELINE ORCHESTRATOR — Strict 3-Layer Enforcement
// ================================================================
// Layer 1: Heuristic Engine (CPU — Fast — Always On)
//   a. DLP → Redact PII / Block if policy=Block
//   b. Injection Scanner → Block if score ≥ threshold
//   c. Threat Engine Signatures → Block if match found
//
// Layer 2: Cognitive Engine (GPU — Optional)
//   RAG context from ThreatEngine → moka cache → Semaphore → LLM
//
// Layer 3: Final Execution
//   Block → 403 | Audit → Log + Header + Forward | Allow → Forward
// ================================================================
async fn handler(
    State(state): State<AppState>,
    method: Method,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let global_start = std::time::Instant::now();
    let path_str = format!("/{}", path);
    tracing::info!("{} request to {}", method, path_str);

    if state.verbose {
        println!("{} {} {}", "INCOMING:".bright_black(), method, path_str);
    }

    // ── Layer 0: Request Smuggling Prevention ──
    // Check for HTTP request smuggling attempts before rate limiting
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
        banner::print_warning(&format!("Request smuggling attempt: {}", block_reason));
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
    // Only validate paths that contain suspicious patterns (traversal attempts)
    // Skip API routes like /v1/chat/completions which start with /
    let is_api_route = path_str.starts_with("/v1/") || path_str.starts_with("/api/");
    let has_traversal =
        path_str.contains("..") || path_str.contains("~") || path_str.contains("//");

    if !is_api_route && has_traversal {
        let path_validation = crate::security::path_security::validate_path(&path_str);
        if !path_validation.valid {
            let error_msg = path_validation
                .errors
                .iter()
                .map(|e| format!("{:?}", e))
                .collect::<Vec<_>>()
                .join(", ");
            banner::print_warning(&format!("Path traversal blocked: {}", error_msg));
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
    }

    // ── Rate Limiting ──
    if let Some(limiter) = &state.rate_limiter {
        let mut lock = limiter.lock().await;
        let now = std::time::Instant::now();
        let entry = lock.entry("global".to_string()).or_insert((0, now));

        if now.duration_since(entry.1).as_secs() >= 60 {
            *entry = (1, now);
        } else if entry.0 >= state.rate_limit_requests_per_minute {
            banner::print_warning("Global Rate Limit Exceeded");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                "{\"error\": \"rate_limit_exceeded\"}\n",
            )
                .into_response();
        } else {
            entry.0 += 1;
        }
    }

    // ── Parse JSON body ──
    if let Ok(mut json_body) = serde_json::from_slice::<Value>(&body) {
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
        // We own the key_env as a String so it can be replaced by the SLB
        // (Addendum 1: the SLB must swap the key when it changes the tier).
        let mut effective_key_env: Option<String> =
            route.and_then(|r| r.key_env.as_ref().map(|s| s.to_string()));

        let mut modified = true;
        let mut risk_level: Option<&str> = None; // For X-Guardian-Risk header in audit mode

        // Accumulates message content for SLB scoring — populated during the scan
        // loop below (Addendum 2: reuse already-parsed text, never re-read the stream).
        let mut content_for_slb = String::new();

        if let Some(messages) = json_body.get_mut("messages").and_then(|m| m.as_array_mut()) {
            for message in messages {
                let role = message
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("user");
                if role != "user" && role != "system" {
                    continue;
                }

                let content_raw = message.get("content").unwrap_or(&Value::Null);
                let content_text = extract_full_content(content_raw);

                if content_text.is_empty() {
                    continue;
                }

                // Accumulate for SLB scoring (safe — already extracted from parsed JSON).
                content_for_slb.push_str(&content_text);
                content_for_slb.push(' ');

                // ════════════════════════════════════════════════════
                // LAYER 1: HEURISTIC ENGINE (CPU — Sub-millisecond)
                // ════════════════════════════════════════════════════

                // ── Step 1a: DLP (Data Loss Prevention) ──
                let dlp_start = std::time::Instant::now();

                // Block Check
                if let Some(violation) =
                    check_for_violations(&content_text, Some(&state.dlp_config))
                {
                    if state.verbose {
                        println!(
                            "   {} DLP violation check: {:?}",
                            "DEBUG:".bright_black(),
                            dlp_start.elapsed()
                        );
                    }

                    if state.dlp_action == DlpAction::Block {
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
                    } else {
                        tracing::info!("DLP: {} detected, redacting", violation.category);
                    }
                }

                // Redaction Process
                let cleaned = redact_pii(&content_text, Some(&state.dlp_config));
                if state.verbose {
                    println!(
                        "   {} DLP redact check: {:?}",
                        "DEBUG:".bright_black(),
                        dlp_start.elapsed()
                    );
                }

                if cleaned != content_text {
                    banner::print_success(&format!(
                        "Redacted sensitive data in request to {}",
                        path_str
                    ));
                    tracing::info!("DLP redaction applied for request to {}", path_str);
                    modified = true;

                    log_security_event(
                        state.audit_log_path.clone(),
                        serde_json::json!({
                            "timestamp": Utc::now().to_rfc3339(),
                            "event": "data_redacted",
                            "path": path_str
                        }),
                    );

                    // Update the message content with redacted text
                    if let Some(content_val) = message.get_mut("content") {
                        if content_val.is_string() {
                            *content_val = Value::String(cleaned.clone());
                        } else if let Some(parts) = content_val.as_array_mut() {
                            for part in parts {
                                if let Some(text_val) = part.get("text").and_then(|t| t.as_str()) {
                                    let part_cleaned =
                                        redact_pii(text_val, Some(&state.dlp_config));
                                    if let Some(t) = part.get_mut("text") {
                                        *t = Value::String(part_cleaned);
                                    }
                                }
                            }
                        }
                    }
                }

                // Get current content text (possibly redacted)
                let current_content =
                    extract_full_content(message.get("content").unwrap_or(&Value::Null));
                let scan_text = if current_content.is_empty() {
                    &content_text
                } else {
                    &current_content
                };

                // ── Unicode Normalization ──
                // Normalize Unicode text to prevent homograph attacks and obfuscation
                let normalized = crate::security::normalize_unicode(scan_text);
                let scan_text = &normalized.normalized;
                // Use normalized text for all subsequent checks

                // ── Step 1b: Injection Scanner ──
                let inj_start = std::time::Instant::now();
                let security_report = analyze_injection(scan_text);
                if state.verbose {
                    println!(
                        "   {} Injection check: {:?} (score={})",
                        "DEBUG:".bright_black(),
                        inj_start.elapsed(),
                        security_report.score
                    );
                }

                if security_report.score >= state.block_threshold {
                    let category_str = format!("{:?}", security_report.category);
                    banner::print_warning(&format!(
                        "Blocked {:?} attempt in {} (score={})",
                        security_report.category, path_str, security_report.score
                    ));

                    log_security_event(
                        state.audit_log_path.clone(),
                        serde_json::json!({
                            "timestamp": Utc::now().to_rfc3339(),
                            "event": "injection_blocked",
                            "path": path_str,
                            "category": category_str,
                            "score": security_report.score
                        }),
                    );

                    match state.default_action {
                        PolicyAction::Audit => {
                            risk_level = Some("High");
                            tracing::warn!("AUDIT: Injection detected (score={}, category={}) but forwarding per audit policy", security_report.score, category_str);
                        }
                        PolicyAction::Allow => {
                            // Allow policy: log but don't block
                            tracing::warn!("ALLOW: Injection detected but policy is 'allow'");
                        }
                        _ => {
                            return block_response(
                                &category_str,
                                "heuristic_injection_detected",
                                "Access Denied: Potential Prompt Injection Detected by Heuristic Guard"
                            );
                        }
                    }
                }

                // ── Step 1c: Threat Engine Scan ──
                let sig_start = std::time::Instant::now();
                let scan_result = state.threat_engine.check(scan_text);

                if state.verbose {
                    println!(
                        "   {} Threat Scan: {:?} (Blocked: {}, RiskTags: {:?})",
                        "DEBUG:".bright_black(),
                        sig_start.elapsed(),
                        scan_result.blocked,
                        scan_result.risk_tags
                    );
                }

                // LAYER 1: HARD SHIELD (Deterministic Block)
                if scan_result.blocked {
                    let tags_str = scan_result.risk_tags.join(", ");
                    banner::print_warning(&format!("BLOCK (Severity 90+): {}", tags_str));

                    log_security_event(
                        state.audit_log_path.clone(),
                        serde_json::json!({
                            "timestamp": Utc::now().to_rfc3339(),
                            "event": "threat_blocked",
                            "path": path_str,
                            "tags": &scan_result.risk_tags,
                            "severity": scan_result.max_severity
                        }),
                    );

                    match state.default_action {
                        PolicyAction::Audit => {
                            risk_level = Some("Critical");
                            tracing::warn!("AUDIT: Threat blocked but forwarding per audit policy");
                        }
                        PolicyAction::Allow => {
                            tracing::warn!("ALLOW: Threat blocked but policy is 'allow'");
                        }
                        _ => {
                            return block_response(
                                "CriticalThreat",
                                "threat_signature_blocked",
                                &format!("Access Denied: Critical Threat Detected ({})", tags_str),
                            );
                        }
                    }
                }

                // ════════════════════════════════════════════════════
                // LAYER 2 & 3: HEURISTIC TAGGING + AI JUDGE
                // ════════════════════════════════════════════════════
                // If not blocked, but has risks (Sev 50-89), consult the Judge.

                let has_risks = !scan_result.risk_tags.is_empty();
                let judge_enabled = state.judge.is_enabled();

                if has_risks && judge_enabled {
                    let judge_start = std::time::Instant::now();

                    // RAG Retrieval for context (even if not strictly blocked, we want similarity)
                    let similar_threats = state.threat_engine.find_similar(scan_text, 0.4);

                    let judge_passed = state
                        .judge
                        .check_prompt(scan_text, &scan_result.risk_tags, &similar_threats)
                        .await;

                    if state.verbose {
                        println!(
                            "   {} AI Judge check: {:?}",
                            "DEBUG:".bright_black(),
                            judge_start.elapsed()
                        );
                    }

                    if !judge_passed {
                        banner::print_error(&format!(
                            "AI Judge blocked request to {}: Violates Safety Policy",
                            path_str
                        ));
                        tracing::error!(
                            "Semantic policy block by AI Judge for request to {}",
                            path_str
                        );

                        log_security_event(
                            state.audit_log_path.clone(),
                            serde_json::json!({
                                "timestamp": Utc::now().to_rfc3339(),
                                "event": "semantic_blocked",
                                "path": path_str,
                                "risk_tags": &scan_result.risk_tags
                            }),
                        );

                        match state.default_action {
                            PolicyAction::Audit => {
                                risk_level = Some("High");
                                tracing::warn!("AUDIT: AI Judge flagged request but forwarding per audit policy");
                            }
                            PolicyAction::Allow => {
                                tracing::warn!(
                                    "ALLOW: AI Judge flagged request but policy is 'allow'"
                                );
                            }
                            _ => {
                                return block_response(
                                    "SemanticViolation",
                                    "semantic_violation_detected",
                                    "Access Denied: Your request was blocked by the AI Governance Engine."
                                );
                            }
                        }
                    }
                }
            }
        }

        // ════════════════════════════════════════════════════
        // SEMANTIC LOAD BALANCER (SLB) — Post-Security Routing
        // ════════════════════════════════════════════════════
        // Runs AFTER security pipeline so DLP + injection checks always fire first.
        // Uses content already collected from the scan loop — no stream re-read.
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

                // Hard Override (Addendum 3): SLB is authoritative.
                upstream_url = decision.upstream_url;

                // Addendum 1 — Header Swap: Replace key_env with the tier's key.
                // If we left the old key, the new upstream would return 401.
                effective_key_env = decision.key_env;

                // Rewrite model in JSON body if tier specifies one.
                if let Some(ref slb_model) = decision.model {
                    if let Some(m_val) = json_body.get_mut("model") {
                        *m_val = serde_json::Value::String(slb_model.clone());
                    }
                    modified = true;
                }
            }
        }

        // ════════════════════════════════════════════════════
        // LAYER 3: FINAL EXECUTION
        // ════════════════════════════════════════════════════
        let final_body = if modified {
            Bytes::from(serde_json::to_vec(&json_body).unwrap_or_else(|_| body.to_vec()))
        } else {
            body.clone()
        };

        banner::print_step(&format!(
            "Forwarding to [{}] target: {}...",
            model_alias, upstream_url
        ));
        let response = match state
            .proxy
            .forward_request(crate::proxy::ForwardOptions {
                upstream_url: &upstream_url,
                api_key_env: effective_key_env.as_deref(),
                method,
                path: &path_str,
                headers,
                body: final_body,
                dlp_config: Some(&state.dlp_config),
                dlp_action: state.dlp_action,
            })
            .await
        {
            Ok(res) => {
                // DLP is now handled inside the proxy!

                // Inject X-Guardian-Risk header in audit mode
                if let Some(level) = risk_level {
                    // We need to clone the response to add headers? No, res is mutable.
                    // But wait, the proxy returns Response, we are in Ok(mut res).
                    let mut response = res;
                    if let Ok(hv) = axum::http::HeaderValue::from_str(level) {
                        response.headers_mut().insert("x-guardian-risk", hv);
                    }
                    tracing::warn!(
                        "AUDIT MODE: Request forwarded with X-Guardian-Risk: {}",
                        level
                    );
                    response
                } else {
                    res
                }
            }
            Err(e) => {
                banner::print_error(&format!("Internal Proxy Error: {}", e));
                let error_msg = serde_json::json!({
                    "error": "proxy_internal_error",
                    "message": format!("Internal failure in proxy: {}", e)
                });
                let body = serde_json::to_string(&error_msg).unwrap_or_default() + "\n";
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body,
                )
                    .into_response()
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
        // SECURITY FIX C1: Non-JSON Request Handling
        // Default-deny non-JSON to prevent security bypasses.
        // If allowed via config, still apply raw byte DLP scanning.
        // ════════════════════════════════════════════════════

        if !state.security_config.allow_non_json_passthrough {
            // SECURITY: Default-deny non-JSON requests
            banner::print_blocking(&format!(
                "Non-JSON request to {}: BLOCKED (security policy)",
                path_str
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
            "Non-JSON passthrough enabled (SECURITY RISK): {}",
            path_str
        ));
        tracing::warn!("SECURITY: Non-JSON passthrough enabled — security checks bypassed!");

        // Even in passthrough mode, attempt basic DLP on raw bytes
        let body_str = String::from_utf8_lossy(&body);
        if let Some(violation) = check_for_violations(&body_str, Some(&state.dlp_config)) {
            banner::print_warning(&format!(
                "DLP violation detected in non-JSON body to {}",
                path_str
            ));
            if state.dlp_action == DlpAction::Block {
                return block_response(
                    &violation.category,
                    "dlp_violation",
                    &format!("Access Denied: {}", violation.description),
                );
            }
        }

        let upstream_url = state.default_upstream.clone();
        let response = match state
            .proxy
            .forward_request(crate::proxy::ForwardOptions {
                upstream_url: &upstream_url,
                api_key_env: None,
                method,
                path: &path_str,
                headers,
                body,
                dlp_config: Some(&state.dlp_config),
                dlp_action: state.dlp_action,
            })
            .await
        {
            Ok(res) => res,
            Err(e) => {
                banner::print_error(&format!("Internal Proxy Error: {}", e));
                let error_msg = serde_json::json!({
                    "error": "proxy_internal_error",
                    "message": format!("Internal failure in proxy: {}", e)
                });
                let body = serde_json::to_string(&error_msg).unwrap_or_default() + "\n";
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body,
                )
                    .into_response()
            }
        };

        if state.verbose {
            banner::print_warning(&format!(
                "Non-JSON passthrough to {}: SECURITY BYPASSED",
                path_str
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
