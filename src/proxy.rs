use crate::banner;
use crate::security::{DlpAction, DlpEngine, DlpViolation, RedactionSession};
use anyhow::{Context, Result};
use axum::response::IntoResponse;
use futures_util::StreamExt;
use http::{HeaderMap, Method, StatusCode};
use open_guardian::secrets::{SecretBroker, SecretRef};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const MAX_INSPECTABLE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
struct ResponseMutation {
    redacted: bool,
    restored: bool,
}

impl ResponseMutation {
    fn merge(&mut self, other: Self) {
        self.redacted |= other.redacted;
        self.restored |= other.restored;
    }
}

#[derive(Debug)]
enum ResponseInspectionError {
    DlpViolation(DlpViolation),
    InvalidJson,
}

fn transform_response_string(
    input: &str,
    dlp_engine: &DlpEngine,
    dlp_action: DlpAction,
    redactions: &RedactionSession,
) -> std::result::Result<(String, ResponseMutation), ResponseInspectionError> {
    if dlp_action == DlpAction::Block {
        if let Some(violation) = dlp_engine.check_violations(input) {
            return Err(ResponseInspectionError::DlpViolation(violation));
        }
    }

    let redacted = if dlp_action == DlpAction::Redact {
        dlp_engine.redact_permanent(input)
    } else {
        input.to_string()
    };
    let restored = redactions.restore(&redacted);

    let mutation = ResponseMutation {
        redacted: redacted != input,
        restored: restored != redacted,
    };
    Ok((restored, mutation))
}

fn transform_json_strings(
    value: &mut serde_json::Value,
    dlp_engine: &DlpEngine,
    dlp_action: DlpAction,
    redactions: &RedactionSession,
) -> std::result::Result<ResponseMutation, ResponseInspectionError> {
    let mut mutation = ResponseMutation::default();

    match value {
        serde_json::Value::String(text) => {
            let (transformed, string_mutation) =
                transform_response_string(text, dlp_engine, dlp_action, redactions)?;
            if string_mutation.redacted || string_mutation.restored {
                *text = transformed;
            }
            mutation.merge(string_mutation);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                mutation.merge(transform_json_strings(
                    value, dlp_engine, dlp_action, redactions,
                )?);
            }
        }
        serde_json::Value::Object(values) => {
            let original = std::mem::take(values);
            for (key, mut value) in original {
                let (key, key_mutation) =
                    transform_response_string(&key, dlp_engine, dlp_action, redactions)?;
                mutation.merge(key_mutation);
                mutation.merge(transform_json_strings(
                    &mut value, dlp_engine, dlp_action, redactions,
                )?);
                if values.insert(key, value).is_some() {
                    return Err(ResponseInspectionError::InvalidJson);
                }
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }

    Ok(mutation)
}

fn is_json_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

fn inspect_json_response(
    body: &str,
    dlp_engine: &DlpEngine,
    dlp_action: DlpAction,
    redactions: &RedactionSession,
) -> std::result::Result<(String, ResponseMutation), ResponseInspectionError> {
    let mut value = serde_json::from_str::<serde_json::Value>(body)
        .map_err(|_| ResponseInspectionError::InvalidJson)?;
    let mutation = transform_json_strings(&mut value, dlp_engine, dlp_action, redactions)?;
    if mutation.redacted || mutation.restored {
        let serialized =
            serde_json::to_string(&value).map_err(|_| ResponseInspectionError::InvalidJson)?;
        Ok((serialized, mutation))
    } else {
        Ok((body.to_string(), mutation))
    }
}

fn inspect_sse_response(
    body: &str,
    dlp_engine: &DlpEngine,
    dlp_action: DlpAction,
    redactions: &RedactionSession,
) -> std::result::Result<(String, ResponseMutation), ResponseInspectionError> {
    let mut output = String::with_capacity(body.len());
    let mut mutation = ResponseMutation::default();

    for segment in body.split_inclusive('\n') {
        let (line, ending) = if let Some(line) = segment.strip_suffix("\r\n") {
            (line, "\r\n")
        } else if let Some(line) = segment.strip_suffix('\n') {
            (line, "\n")
        } else {
            (segment, "")
        };

        let Some(after_field) = line.strip_prefix("data:") else {
            output.push_str(line);
            output.push_str(ending);
            continue;
        };
        let separator_len = usize::from(after_field.starts_with(' '));
        let prefix_len = "data:".len() + separator_len;
        let payload = &line[prefix_len..];

        if payload == "[DONE]" || payload.is_empty() {
            output.push_str(line);
            output.push_str(ending);
            continue;
        }

        let (transformed, line_mutation) =
            if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(payload) {
                let line_mutation =
                    transform_json_strings(&mut value, dlp_engine, dlp_action, redactions)?;
                if line_mutation.redacted || line_mutation.restored {
                    (
                        serde_json::to_string(&value)
                            .map_err(|_| ResponseInspectionError::InvalidJson)?,
                        line_mutation,
                    )
                } else {
                    (payload.to_string(), line_mutation)
                }
            } else {
                transform_response_string(payload, dlp_engine, dlp_action, redactions)?
            };

        output.push_str(&line[..prefix_len]);
        output.push_str(&transformed);
        output.push_str(ending);
        mutation.merge(line_mutation);
    }

    Ok((output, mutation))
}

fn inspect_response_text(
    body: &str,
    content_type: &str,
    dlp_engine: &DlpEngine,
    dlp_action: DlpAction,
    redactions: &RedactionSession,
) -> std::result::Result<(String, ResponseMutation), ResponseInspectionError> {
    if body.is_empty() {
        return Ok((String::new(), ResponseMutation::default()));
    }

    if content_type.contains("text/event-stream") {
        inspect_sse_response(body, dlp_engine, dlp_action, redactions)
    } else if is_json_content_type(content_type) {
        inspect_json_response(body, dlp_engine, dlp_action, redactions)
    } else {
        transform_response_string(body, dlp_engine, dlp_action, redactions)
    }
}

fn append_response_chunk(buffer: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<()> {
    if buffer.len().saturating_add(chunk.len()) > limit {
        anyhow::bail!("upstream response exceeds the {limit} byte inspection limit");
    }
    buffer.extend_from_slice(chunk);
    Ok(())
}

async fn read_response_body(response: reqwest::Response) -> Result<Vec<u8>> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read upstream response body")?;
        append_response_chunk(&mut body, &chunk, MAX_INSPECTABLE_RESPONSE_BYTES)?;
    }

    Ok(body)
}

fn build_bearer_header(raw_key: &str) -> Result<reqwest::header::HeaderValue> {
    let trimmed = raw_key.trim();
    let clean_key = if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };

    if clean_key.is_empty() {
        anyhow::bail!("configured API key is empty");
    }

    let authorization = Zeroizing::new(format!("Bearer {clean_key}"));
    let mut header = reqwest::header::HeaderValue::from_str(authorization.as_str())
        .context("configured API key cannot be encoded as an Authorization header")?;
    header.set_sensitive(true);
    Ok(header)
}

fn build_target_url(base_url: &str, path: &str) -> Result<reqwest::Url> {
    let base = reqwest::Url::parse(base_url).context("configured upstream URL is invalid")?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.cannot_be_a_base()
    {
        anyhow::bail!("configured upstream URL violates the endpoint policy");
    }

    let mut target_path = path;
    let normalized_base = base_url.trim_end_matches('/');
    if normalized_base.ends_with("/v1") && target_path.starts_with("/v1") {
        target_path = &target_path[3..];
    }
    if !target_path.is_empty() && !target_path.starts_with('/') {
        anyhow::bail!("upstream request path must be absolute");
    }

    reqwest::Url::parse(&format!("{normalized_base}{target_path}"))
        .context("upstream target URL is invalid")
}

/// All parameters needed to forward a single request upstream.
/// Bundles the args to keep `forward_request` within clippy::too_many_arguments limits.
pub struct ForwardOptions<'a> {
    pub upstream_url: &'a str,
    pub credential: Option<&'a SecretRef>,
    pub method: Method,
    pub path: &'a str,
    pub headers: HeaderMap,
    pub body: axum::body::Bytes,
    pub dlp_engine: &'a DlpEngine,
    pub dlp_action: DlpAction,
    pub redactions: RedactionSession,
}

#[derive(Clone)]
pub struct ProxyClient {
    client: Client,
    secret_broker: Arc<SecretBroker>,
}

impl ProxyClient {
    pub fn new(timeout_seconds: u64, secret_broker: Arc<SecretBroker>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .build()
            .context("Failed to build reqwest client")?;

        Ok(Self {
            client,
            secret_broker,
        })
    }

    pub async fn forward_request(
        &self,
        opts: ForwardOptions<'_>,
    ) -> Result<axum::response::Response> {
        let ForwardOptions {
            upstream_url,
            credential,
            method,
            path,
            mut headers,
            body,
            dlp_engine,
            dlp_action,
            redactions,
        } = opts;
        let url = build_target_url(upstream_url, path)?;

        // Strip transfer-encoding and remaining hop-by-hop headers before
        // forwarding; the smuggling check already rejected the dangerous
        // combinations upstream of this point.
        crate::security::smuggling::sanitize_headers(&mut headers);

        let mut request_builder = self.client.request(method, url).body(body);

        if let Some(reference) = credential {
            let secret = self
                .secret_broker
                .resolve(reference)
                .await
                .with_context(|| format!("failed to resolve provider credential {reference}"))?;
            let authorization = build_bearer_header(secret.expose_secret())?;
            tracing::info!("SEC: provider credential resolved via SecretBroker");
            request_builder = request_builder.header(reqwest::header::AUTHORIZATION, authorization);
        }

        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();
            if name_str != "host"
                && name_str != "content-length"
                && name_str != "accept-encoding"
                && name_str != "authorization"
            {
                if let (Ok(hn), Ok(hv)) = (
                    name.as_str().parse::<reqwest::header::HeaderName>(),
                    reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    request_builder = request_builder.header(hn, hv);
                }
            }
        }

        request_builder = request_builder.header(reqwest::header::ACCEPT_ENCODING, "gzip, br");

        let response = match request_builder.send().await {
            Ok(resp) => {
                banner::print_success(&format!("Upstream responded: {}", resp.status()));
                resp
            }
            Err(e) => {
                banner::print_error(&format!("Upstream request failed: {e}"));
                let status = if e.is_timeout() {
                    StatusCode::GATEWAY_TIMEOUT
                } else {
                    StatusCode::BAD_GATEWAY
                };

                let detail = if e.is_timeout() {
                    "upstream_timeout"
                } else {
                    "upstream_unavailable"
                };
                let error_json = serde_json::json!({
                    "error": "upstream_error",
                    "details": detail
                });

                let body_str = serde_json::to_string(&error_json)
                    .unwrap_or_else(|_| "{\"error\": \"upstream_error\"}".to_string());

                return Ok(axum::response::Response::builder()
                    .status(status)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(body_str))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()));
            }
        };

        let mut res_builder =
            axum::response::Response::builder().status(response.status().as_u16());

        for (name, value) in response.headers().iter() {
            let name_str = name.as_str().to_lowercase();
            if name_str != "content-length"
                && name_str != "transfer-encoding"
                && name_str != "content-encoding"
                && name_str != "connection"
                && name_str != "keep-alive"
            {
                res_builder = res_builder.header(name.as_str(), value.as_bytes());
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // SECURITY FIX C5: Streaming Response Handling
        // ═══════════════════════════════════════════════════════════════

        // Check if this is a streaming response (text/event-stream)
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let is_sse = content_type.contains("text/event-stream");

        if is_sse {
            // Releasing partial events before a secret pattern is complete would
            // let values bypass DLP at arbitrary chunk boundaries. Buffer first.
            banner::print_info(&format!(
                "Buffering SSE response from {path} for DLP inspection"
            ));
        }

        // All responses are bounded and buffered before DLP. This deliberately
        // trades token-by-token delivery for a security boundary that cannot be
        // bypassed by splitting a secret across network chunks or SSE events.
        let bytes = read_response_body(response).await?;

        // A byte sequence that cannot be decoded as UTF-8 cannot pass text DLP.
        // Fail closed instead of silently releasing an uninspectable body.
        let body_text = match String::from_utf8(bytes) {
            Ok(body) => body,
            Err(_) => {
                banner::print_warning(&format!("Response DLP BLOCKED: non-UTF-8 body from {path}"));
                let error_json = serde_json::json!({
                    "error": "upstream_response_uninspectable",
                    "details": "response_body_is_not_utf8"
                });
                return Ok(axum::response::Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(serde_json::to_string(&error_json)?))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()));
            }
        };

        let (body_final, mutation) = match inspect_response_text(
            &body_text,
            &content_type,
            dlp_engine,
            dlp_action,
            &redactions,
        ) {
            Ok(inspected) => inspected,
            Err(ResponseInspectionError::DlpViolation(violation)) => {
                banner::print_warning(&format!(
                    "Response DLP BLOCKED: {} leak detected in response from {}",
                    violation.description, path
                ));
                let error_json = serde_json::json!({
                   "error": "policy_violation",
                   "category": violation.category,
                   "details": "response_dlp_leak",
                   "message": format!("Response contains prohibited data: {}", violation.description)
                });

                return Ok(axum::response::Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(serde_json::to_string(&error_json)?))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()));
            }
            Err(ResponseInspectionError::InvalidJson) => {
                banner::print_warning(&format!(
                    "Response DLP BLOCKED: malformed JSON body from {path}"
                ));
                let error_json = serde_json::json!({
                    "error": "upstream_response_uninspectable",
                    "details": "response_body_is_invalid_json"
                });
                return Ok(axum::response::Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(serde_json::to_string(&error_json)?))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()));
            }
        };

        if mutation.redacted {
            banner::print_success(&format!("Redacted sensitive data in response from {path}"));
            tracing::info!("DLP: Redacted response from {}", path);
        }
        if mutation.restored {
            tracing::info!(
                "DLP: restored {} request-scoped placeholder(s) locally",
                redactions.redaction_count()
            );
        }

        Ok(res_builder
            .body(axum::body::Body::from(body_final.into_bytes()))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        append_response_chunk, build_bearer_header, build_target_url, inspect_response_text,
        ResponseInspectionError,
    };
    use crate::config::DlpConfig;
    use crate::security::{DlpAction, DlpEngine, RedactionSession};
    use async_trait::async_trait;
    use axum::{http::StatusCode, routing::any, Router};
    use open_guardian::secrets::{
        SecretBackend, SecretBroker, SecretError, SecretRef, SecretValue,
    };
    use std::sync::Arc;

    struct FixedCredentialBackend;

    #[async_trait]
    impl SecretBackend for FixedCredentialBackend {
        fn scheme(&self) -> &'static str {
            "test"
        }

        async fn resolve(&self, _reference: &SecretRef) -> Result<SecretValue, SecretError> {
            SecretValue::new("broker-token".to_string())
        }
    }

    /// Full engine with the real `rules/secrets.toml` (tests run from the
    /// package root, so the default relative path resolves).
    fn engine() -> DlpEngine {
        DlpEngine::build(&DlpConfig::default()).expect("rules load")
    }

    #[test]
    fn bearer_header_is_sensitive_and_trims_wrapping_quotes() {
        let header = build_bearer_header("  \"test-token\"  ").expect("valid key");

        assert_eq!(header.to_str().expect("ASCII header"), "Bearer test-token");
        assert!(header.is_sensitive());
    }

    #[test]
    fn bearer_header_rejects_empty_keys() {
        assert!(build_bearer_header("  ''  ").is_err());
    }

    #[test]
    fn bearer_header_rejects_header_injection() {
        assert!(build_bearer_header("token\r\nx-forged: true").is_err());
    }

    #[test]
    fn response_buffer_enforces_inspection_limit() {
        let mut buffer = vec![0; 4];

        assert!(append_response_chunk(&mut buffer, &[1, 2, 3, 4], 8).is_ok());
        assert!(append_response_chunk(&mut buffer, &[5], 8).is_err());
        assert_eq!(buffer.len(), 8);
    }

    #[test]
    fn json_response_dlp_never_rewrites_numeric_metadata() {
        let body = r#"{"created":1784428111,"queue_time":0.172,"seed":1844674407370955,"choices":[{"message":{"content":"GUARDIAN_GROQ_OK"}}]}"#;
        let session = RedactionSession::new();

        let (inspected, mutation) = inspect_response_text(
            body,
            "application/json",
            &engine(),
            DlpAction::Redact,
            &session,
        )
        .expect("valid Groq-style response");

        assert_eq!(inspected, body);
        assert!(!mutation.redacted);
        assert!(!mutation.restored);
        let parsed: serde_json::Value = serde_json::from_str(&inspected).expect("valid JSON");
        assert_eq!(parsed["created"], 1_784_428_111_u64);
        assert_eq!(parsed["queue_time"], 0.172);
        assert_eq!(parsed["seed"], 1_844_674_407_370_955_u64);
    }

    #[test]
    fn json_response_dlp_redacts_strings_without_changing_value_types() {
        let body = r#"{"created":1784428111,"message":"gsk_abcdefghijklmnopqrstuvwxyz"}"#;
        let session = RedactionSession::new();

        let (inspected, mutation) = inspect_response_text(
            body,
            "application/json; charset=utf-8",
            &engine(),
            DlpAction::Redact,
            &session,
        )
        .expect("inspect response");

        let parsed: serde_json::Value = serde_json::from_str(&inspected).expect("valid JSON");
        assert_eq!(parsed["created"], 1_784_428_111_u64);
        assert_eq!(parsed["message"], "<GROQ-API-KEY>");
        assert!(mutation.redacted);
    }

    #[test]
    fn json_response_dlp_also_inspects_object_keys() {
        let body = r#"{"gsk_abcdefghijklmnopqrstuvwxyz":"value"}"#;
        let session = RedactionSession::new();

        let (inspected, mutation) = inspect_response_text(
            body,
            "application/json",
            &engine(),
            DlpAction::Redact,
            &session,
        )
        .expect("inspect response");

        let parsed: serde_json::Value = serde_json::from_str(&inspected).expect("valid JSON");
        assert_eq!(parsed["<GROQ-API-KEY>"], "value");
        assert!(mutation.redacted);
    }

    #[test]
    fn empty_json_response_body_is_valid_for_head_and_no_content() {
        let session = RedactionSession::new();

        let (inspected, mutation) = inspect_response_text(
            "",
            "application/json",
            &engine(),
            DlpAction::Redact,
            &session,
        )
        .expect("empty body");

        assert!(inspected.is_empty());
        assert!(!mutation.redacted);
        assert!(!mutation.restored);
    }

    #[test]
    fn response_placeholder_restoration_remains_valid_json() {
        let original = r#"api_key="abcdefghijklmnopqrstuvwxyz123456""#;
        let mut session = RedactionSession::new();
        let placeholder = session.redact(original, &engine());
        let body = serde_json::json!({ "message": placeholder }).to_string();

        let (inspected, mutation) = inspect_response_text(
            &body,
            "application/json",
            &engine(),
            DlpAction::Redact,
            &session,
        )
        .expect("inspect response");

        let parsed: serde_json::Value = serde_json::from_str(&inspected).expect("valid JSON");
        assert_eq!(parsed["message"], original);
        assert!(mutation.restored);
    }

    #[test]
    fn sse_response_dlp_preserves_numeric_json_fields() {
        let body =
            "data: {\"created\":1784428111,\"delta\":{\"content\":\"ok\"}}\n\ndata: [DONE]\n\n";
        let session = RedactionSession::new();

        let (inspected, mutation) = inspect_response_text(
            body,
            "text/event-stream",
            &engine(),
            DlpAction::Redact,
            &session,
        )
        .expect("inspect SSE");

        assert_eq!(inspected, body);
        assert!(!mutation.redacted);
    }

    #[test]
    fn declared_json_that_cannot_be_parsed_fails_closed() {
        let session = RedactionSession::new();
        let result = inspect_response_text(
            "{not-json}",
            "application/problem+json",
            &engine(),
            DlpAction::Redact,
            &session,
        );

        assert!(matches!(result, Err(ResponseInspectionError::InvalidJson)));
    }

    #[test]
    fn target_url_normalizes_v1_and_rejects_embedded_credentials() {
        let url = build_target_url("https://example.invalid/v1/", "/v1/chat/completions")
            .expect("valid target");

        assert_eq!(url.as_str(), "https://example.invalid/v1/chat/completions");
        assert!(build_target_url(
            "https://user:secret@example.invalid/v1",
            "/v1/chat/completions"
        )
        .is_err());
        assert!(build_target_url(
            "https://example.invalid/v1?api_key=secret",
            "/v1/chat/completions"
        )
        .is_err());
    }

    #[tokio::test]
    async fn provider_credential_is_resolved_only_into_authorization_header() {
        let app = Router::new().route(
            "/probe",
            any(|headers: axum::http::HeaderMap| async move {
                match headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                {
                    Some("Bearer broker-token") => StatusCode::NO_CONTENT,
                    _ => StatusCode::UNAUTHORIZED,
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve test request");
        });

        let mut broker = SecretBroker::new();
        broker
            .register(FixedCredentialBackend)
            .expect("register backend");
        let proxy = super::ProxyClient::new(5, Arc::new(broker)).expect("proxy client");
        let reference: SecretRef = "{{secret:test://provider/api-key}}"
            .parse()
            .expect("credential reference");

        let response = proxy
            .forward_request(super::ForwardOptions {
                upstream_url: &format!("http://{address}"),
                credential: Some(&reference),
                method: axum::http::Method::POST,
                path: "/probe",
                headers: axum::http::HeaderMap::new(),
                body: axum::body::Bytes::from_static(b"{}"),
                dlp_engine: &DlpEngine::builtin_only(&DlpConfig::default()),
                dlp_action: crate::security::DlpAction::Redact,
                redactions: crate::security::RedactionSession::new(),
            })
            .await
            .expect("forward request");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        server.abort();
    }

    #[tokio::test]
    async fn request_placeholders_are_restored_only_after_upstream_returns() {
        let app = Router::new().route("/echo", any(|body: String| async move { body }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve test request");
        });

        let broker = SecretBroker::new();
        let proxy = super::ProxyClient::new(5, Arc::new(broker)).expect("proxy client");
        let original = "Deploy to 192.168.10.25";
        let mut redactions = crate::security::RedactionSession::new();
        let protected =
            redactions.redact(original, &DlpEngine::builtin_only(&DlpConfig::default()));
        assert!(!protected.contains("192.168.10.25"));

        let response = proxy
            .forward_request(super::ForwardOptions {
                upstream_url: &format!("http://{address}"),
                credential: None,
                method: axum::http::Method::POST,
                path: "/echo",
                headers: axum::http::HeaderMap::new(),
                body: axum::body::Bytes::from(protected),
                dlp_engine: &DlpEngine::builtin_only(&DlpConfig::default()),
                dlp_action: crate::security::DlpAction::Redact,
                redactions,
            })
            .await
            .expect("forward request");
        let response_body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("read response");

        assert_eq!(response_body.as_ref(), original.as_bytes());
        server.abort();
    }

    #[tokio::test]
    async fn non_utf8_upstream_response_fails_closed() {
        let app = Router::new().route(
            "/binary",
            any(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                    axum::body::Bytes::from_static(&[0xff, 0xfe, 0xfd]),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve test request");
        });

        let proxy =
            super::ProxyClient::new(5, Arc::new(SecretBroker::new())).expect("proxy client");
        let response = proxy
            .forward_request(super::ForwardOptions {
                upstream_url: &format!("http://{address}"),
                credential: None,
                method: axum::http::Method::GET,
                path: "/binary",
                headers: axum::http::HeaderMap::new(),
                body: axum::body::Bytes::new(),
                dlp_engine: &DlpEngine::builtin_only(&DlpConfig::default()),
                dlp_action: crate::security::DlpAction::Redact,
                redactions: crate::security::RedactionSession::new(),
            })
            .await
            .expect("forward request");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let response_body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("read response");
        assert!(!response_body.as_ref().contains(&0xff));
        server.abort();
    }

    #[tokio::test]
    async fn upstream_network_errors_do_not_disclose_target_details() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve address");
        let address = listener.local_addr().expect("test address");
        drop(listener);

        let proxy =
            super::ProxyClient::new(1, Arc::new(SecretBroker::new())).expect("proxy client");
        let response = proxy
            .forward_request(super::ForwardOptions {
                upstream_url: &format!("http://{address}"),
                credential: None,
                method: axum::http::Method::GET,
                path: "/private-path",
                headers: axum::http::HeaderMap::new(),
                body: axum::body::Bytes::new(),
                dlp_engine: &DlpEngine::builtin_only(&DlpConfig::default()),
                dlp_action: crate::security::DlpAction::Redact,
                redactions: crate::security::RedactionSession::new(),
            })
            .await
            .expect("proxy returns a controlled error response");
        assert!(matches!(
            response.status(),
            StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
        ));
        let response_body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("read response");
        let response_text = String::from_utf8(response_body.to_vec()).expect("UTF-8 response");
        let response_json: serde_json::Value =
            serde_json::from_str(&response_text).expect("controlled JSON error");

        assert!(!response_text.contains(&address.to_string()));
        assert!(!response_text.contains("private-path"));
        assert_eq!(response_json["error"], "upstream_error");
        assert!(matches!(
            response_json["details"].as_str(),
            Some("upstream_unavailable" | "upstream_timeout")
        ));
    }
}
