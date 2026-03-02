//! Security Pipeline Modules
//!
//! This module contains the security processing pipeline components
//! that operate on extracted request data.
//!
//! INFRASTRUCTURE (v0.1.5): These exports are ready for integration
//! to enable C2-C4 security scanning improvements.

#![allow(dead_code)]

pub mod extract;

// NOTE: These exports are for future integration (C2 expanded scan coverage)
#[allow(unused_imports)]
pub use extract::{extract_scan_targets, ScanTarget, TargetKind};
