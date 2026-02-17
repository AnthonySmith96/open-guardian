use crate::banner;
use anyhow::{Context, Result};
use axum::response::IntoResponse;
use futures_util::StreamExt;
use http::{HeaderMap, Method, StatusCode};
use reqwest::Client;
use std::time::Duration;

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
        upstream_url: &str,
        api_key_env: Option<&str>,
        method: Method,
        path: &str,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> Result<axum::response::Response> {
        let base_url = upstream_url;
        let mut target_path = path;

        if base_url.ends_with("/v1") && target_path.starts_with("/v1") {
            target_path = &target_path[3..];
        } else if base_url.ends_with("/v1/") && target_path.starts_with("/v1") {
            target_path = &target_path[3..];
        }

        let url = format!("{}{}", base_url, target_path);

        let mut request_builder = self.client.request(method, &url).body(body);

        if let Some(env_name) = api_key_env {
            if let Ok(key) = std::env::var(env_name) {
                let clean_key = key.trim().replace('\"', "").replace('\'', "");

                // Security-safe log for validation
                if clean_key.len() >= 8 {
                    tracing::info!(
                        "SEC: Injecting key from {} (Length: {}, First 4: {}, Last 4: {})",
                        env_name,
                        clean_key.len(),
                        &clean_key[..4],
                        &clean_key[clean_key.len() - 4..]
                    );
                } else {
                    tracing::warn!(
                        "SEC: Injecting VERY SHORT key from {} (Length: {})",
                        env_name,
                        clean_key.len()
                    );
                }

                match reqwest::header::HeaderValue::from_str(&format!("Bearer {}", clean_key)) {
                    Ok(hv) => {
                        request_builder =
                            request_builder.header(reqwest::header::AUTHORIZATION, hv);
                    }
                    Err(e) => {
                        banner::print_error(&format!("Critical Security Error: Invalid API Key format in {} ({}). Skipping injection.", env_name, e));
                    }
                }
            } else {
                tracing::error!("SEC: Environment variable {} NOT FOUND", env_name);
            }
        }

        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();
            if name_str != "host"
                && name_str != "content-length"
                && name_str != "accept-encoding"
                && name_str != "authorization"
            {
                match (
                    name.as_str().parse::<reqwest::header::HeaderName>(),
                    reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    (Ok(hn), Ok(hv)) => {
                        request_builder = request_builder.header(hn, hv);
                    }
                    _ => {}
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

        // Check if this is a streaming SSE response
        let is_sse = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("text/event-stream"))
            .unwrap_or(false);

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

        if is_sse {
            // Stream SSE responses directly without buffering
            let stream = response.bytes_stream().map(|chunk| {
                chunk
                    .map(|b| axum::body::Bytes::from(b.to_vec()))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            });
            let body = axum::body::Body::from_stream(stream);
            Ok(res_builder
                .body(body)
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
        } else {
            let mut bytes = response
                .bytes()
                .await
                .context("Failed to read upstream response body")?
                .to_vec();

            if bytes.last() != Some(&b'\n') {
                bytes.push(b'\n');
            }

            Ok(res_builder
                .body(axum::body::Body::from(bytes))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
        }
    }
}
