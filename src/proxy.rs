use crate::banner;
use crate::config::DlpConfig;
use crate::security::{check_for_violations, redact_pii, DlpAction};
use anyhow::{Context, Result};
use axum::response::IntoResponse;
use futures_util::StreamExt;
use http::{HeaderMap, Method, StatusCode};
use reqwest::Client;
use std::time::Duration;

const MAX_INSPECTABLE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn append_response_chunk(buffer: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<()> {
    if buffer.len().saturating_add(chunk.len()) > limit {
        anyhow::bail!(
            "upstream response exceeds the {} byte inspection limit",
            limit
        );
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

    let mut header = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", clean_key))
        .context("configured API key cannot be encoded as an Authorization header")?;
    header.set_sensitive(true);
    Ok(header)
}

fn load_authorization_header(env_name: &str) -> Result<reqwest::header::HeaderValue> {
    let key = std::env::var(env_name).with_context(|| {
        format!(
            "required credential environment variable '{}' is unavailable",
            env_name
        )
    })?;
    build_bearer_header(&key).with_context(|| {
        format!(
            "credential from environment variable '{}' is invalid",
            env_name
        )
    })
}

/// All parameters needed to forward a single request upstream.
/// Bundles the args to keep `forward_request` within clippy::too_many_arguments limits.
pub struct ForwardOptions<'a> {
    pub upstream_url: &'a str,
    pub api_key_env: Option<&'a str>,
    pub method: Method,
    pub path: &'a str,
    pub headers: HeaderMap,
    pub body: axum::body::Bytes,
    pub dlp_config: Option<&'a DlpConfig>,
    pub dlp_action: DlpAction,
}

#[derive(Clone)]
pub struct ProxyClient {
    client: Client,
}

impl ProxyClient {
    pub fn new(timeout_seconds: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .build()
            .context("Failed to build reqwest client")?;

        Ok(Self { client })
    }

    pub async fn forward_request(
        &self,
        opts: ForwardOptions<'_>,
    ) -> Result<axum::response::Response> {
        let ForwardOptions {
            upstream_url,
            api_key_env,
            method,
            path,
            headers,
            body,
            dlp_config,
            dlp_action,
        } = opts;
        let base_url = upstream_url;
        let mut target_path = path;

        if (base_url.ends_with("/v1") || base_url.ends_with("/v1/"))
            && target_path.starts_with("/v1")
        {
            target_path = &target_path[3..];
        }

        let url = format!("{}{}", base_url, target_path);

        let mut request_builder = self.client.request(method, &url).body(body);

        if let Some(env_name) = api_key_env {
            let authorization = load_authorization_header(env_name)?;
            tracing::info!(
                "SEC: credential loaded from environment variable '{}'",
                env_name
            );
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
                banner::print_error(&format!("Upstream request failed: {}", e));
                let status = if e.is_timeout() {
                    StatusCode::GATEWAY_TIMEOUT
                } else {
                    StatusCode::BAD_GATEWAY
                };

                let error_json = serde_json::json!({
                    "error": "upstream_error",
                    "details": format!("{}", e)
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
            .unwrap_or("");

        let is_sse = content_type.contains("text/event-stream");

        if is_sse {
            // Releasing partial events before a secret pattern is complete would
            // let values bypass DLP at arbitrary chunk boundaries. Buffer first.
            banner::print_info(&format!(
                "Buffering SSE response from {} for DLP inspection",
                target_path
            ));
        }

        // All responses are bounded and buffered before DLP. This deliberately
        // trades token-by-token delivery for a security boundary that cannot be
        // bypassed by splitting a secret across network chunks or SSE events.
        let bytes = read_response_body(response).await?;

        // ── Response DLP and Body Reconstruction ──
        // We must perform DLP on the response body bytes.
        // If it's JSON/Text, we convert to string (lossy), check violations/redact,
        // and then reconstruct the body.

        // Try to interpret as text for DLP
        // Note: This is a simple heuristic. Ideally we'd check Content-Type.
        // But for v0.1.4 hotfix, we do best-effort string conversion.
        let mut body_final = bytes.clone();

        if let Ok(body_text) = String::from_utf8(bytes.clone()) {
            // 1. Check Violations (Block Mode)
            if let Some(violation) = check_for_violations(&body_text, dlp_config) {
                if dlp_action == DlpAction::Block {
                    banner::print_warning(&format!(
                        "Response DLP BLOCKED: {} leak detected in response from {}",
                        violation.description, target_path
                    ));
                    // Return 403
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
            }

            // 2. Redact (Redact Mode)
            // We always run redaction if not blocked, to be safe.
            // (If action is Block, we already returned. If Allow, we technically shouldn't,
            // but dlp_action usually only has Block/Redact in this context).
            let redacted_text = redact_pii(&body_text, dlp_config);
            if redacted_text != body_text {
                banner::print_success(&format!(
                    "Redacted sensitive data in response from {}",
                    target_path
                ));
                tracing::info!("DLP: Redacted response from {}", target_path);
                body_final = redacted_text.into_bytes();
            }
        }

        if body_final.last() != Some(&b'\n') {
            body_final.push(b'\n');
        }

        // Remove Content-Length as it might have changed
        if res_builder
            .headers_ref()
            .unwrap()
            .contains_key(http::header::CONTENT_LENGTH)
        {
            res_builder
                .headers_mut()
                .unwrap()
                .remove(http::header::CONTENT_LENGTH);
        }

        Ok(res_builder
            .body(axum::body::Body::from(body_final))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
    }
}

#[cfg(test)]
mod tests {
    use super::{append_response_chunk, build_bearer_header};

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
}
