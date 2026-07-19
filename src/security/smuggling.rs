//! HTTP Request Smuggling Prevention
//!
//! This module implements protection against HTTP request smuggling attacks by
//! filtering and blocking dangerous headers, particularly Transfer-Encoding.

use http::{HeaderMap, HeaderName};
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

/// Configuration for request smuggling protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmugglingProtectionConfig {
    #[serde(default = "default_true")]
    pub block_transfer_encoding: bool,
    #[serde(default)]
    pub allowed_transfer_encoding: Vec<String>,
    #[serde(default = "default_true")]
    pub reject_ambiguous_requests: bool,
    #[serde(default = "default_true")]
    pub require_content_length: bool,
    #[serde(default = "default_true")]
    pub log_blocked_requests: bool,
}

impl Default for SmugglingProtectionConfig {
    fn default() -> Self {
        Self {
            block_transfer_encoding: true,
            allowed_transfer_encoding: Vec::new(),
            reject_ambiguous_requests: true,
            require_content_length: true,
            log_blocked_requests: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderSecurityResult {
    pub blocked: bool,
    pub reason: Option<String>,
    pub warnings: Vec<String>,
    pub modified: bool,
}

const SUSPICIOUS_TE_VALUES: &[&str] = &["chunked", "compress", "deflate", "gzip", "identity"];

pub fn check_request_headers(
    headers: &HeaderMap,
    method: &str,
    config: &SmugglingProtectionConfig,
) -> HeaderSecurityResult {
    let mut warnings = Vec::new();
    let mut blocked = false;
    let mut reason = None;
    let modified = false;

    let method_upper = method.to_uppercase();
    let is_request_with_body = matches!(method_upper.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");

    let has_te = headers.contains_key("transfer-encoding");
    let te_value = if has_te {
        headers
            .get("transfer-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase())
    } else {
        None
    };

    let has_cl = headers.contains_key("content-length");
    let cl_value = if has_cl {
        headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    };

    if has_te {
        if let Some(ref te) = te_value {
            let is_allowed = config
                .allowed_transfer_encoding
                .iter()
                .any(|allowed| te.contains(&allowed.to_lowercase()));

            if config.block_transfer_encoding && !is_allowed {
                let is_suspicious = SUSPICIOUS_TE_VALUES
                    .iter()
                    .any(|suspicious| te.contains(*suspicious));

                if is_suspicious {
                    blocked = true;
                    reason = Some(format!(
                        "Transfer-Encoding header contains dangerous value '{te}' - potential request smuggling"
                    ));

                    if config.log_blocked_requests {
                        tracing::error!(
                            "SEC: Request smuggling attempt blocked - Transfer-Encoding: {}",
                            te
                        );
                    }
                }
            }
        }
    }

    if !blocked && has_te && has_cl && config.reject_ambiguous_requests {
        blocked = true;
        reason = Some(
            "Ambiguous request: contains both Transfer-Encoding and Content-Length headers."
                .to_string(),
        );

        if config.log_blocked_requests {
            tracing::error!(
                "SEC: Request smuggling attempt blocked - Ambiguous request (CL: {:?}, TE: {:?})",
                cl_value,
                te_value
            );
        }
    }

    if !blocked && is_request_with_body && config.require_content_length && !has_cl {
        warnings.push("Request with body but no Content-Length header".to_string());
    }

    if let Some(ref cl_str) = cl_value {
        if cl_str.parse::<u64>().is_err() {
            warnings.push(format!("Invalid Content-Length value: {cl_str}"));
        }
    }

    HeaderSecurityResult {
        blocked,
        reason,
        warnings,
        modified,
    }
}

pub fn sanitize_headers(headers: &mut HeaderMap) {
    if headers.contains_key("transfer-encoding") {
        headers.remove("transfer-encoding");
        tracing::debug!("SEC: Removed Transfer-Encoding header from request");
    }

    let hop_by_hop = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];

    for header in hop_by_hop {
        if header != "te" && header != "connection" && header != "keep-alive" {
            // HeaderName::from_static returns HeaderName directly in newer versions
            let name = HeaderName::from_static(header);
            headers.remove(name);
        }
    }
}

pub fn smuggling_blocked_response(reason: &str) -> (u16, String) {
    let body = serde_json::json!({
        "error": "request_blocked",
        "reason": "http_request_smuggling_detected",
        "details": reason,
        "message": "This request was blocked due to potential HTTP request smuggling"
    });

    let body_str = serde_json::to_string(&body).unwrap_or_default();

    (400, body_str)
}
