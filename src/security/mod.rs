//! Security pipeline for the egress proxy.
//!
//! - [`dlp`]: the DLP engine (built-in PII + gitleaks-format secret rules).
//! - [`normalizer`]: evasion-resistant normalization for detection.
//! - [`rate_limit`]: per-client-IP token buckets.
//! - [`smuggling`]: request smuggling header checks.
//! - [`integrity`]: HMAC manifests for the rule files.

pub mod dlp;
pub mod integrity;
pub mod normalizer;
pub mod rate_limit;
pub mod smuggling;

pub use dlp::{DlpAction, DlpEngine, DlpViolation, RedactionSession};
pub use normalizer::normalize_for_matching;
pub use rate_limit::{PerIpRateLimiter, DEFAULT_REQUESTS_PER_MINUTE};
