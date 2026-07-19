pub mod dlp;
pub mod injection_scanner;
pub mod judge;
pub mod normalizer;
pub mod threat_engine;

// New Phase 1-2 security modules (designed, not yet fully wired)
#[allow(dead_code)]
pub mod env_security;
#[allow(dead_code)]
pub mod integrity;
#[allow(dead_code)]
pub mod path_security;
#[allow(dead_code)]
pub mod rate_limit;
#[allow(dead_code)]
pub mod smuggling;

pub use dlp::{check_for_violations, redact_pii, DlpAction, RedactionSession};
pub use injection_scanner::analyze_injection;
pub use judge::Judge;
pub use normalizer::normalize_unicode;
pub use threat_engine::ThreatEngine;
