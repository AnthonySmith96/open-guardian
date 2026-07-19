//! Security Pipeline Modules
//!
//! This module contains the security processing pipeline components
//! that operate on extracted request data.
//!
//! Request extraction is part of the active proxy security path. Any new
//! OpenAI-compatible text field must be added here and covered by tests.

#![allow(dead_code)]

pub mod extract;

#[allow(unused_imports)]
pub use extract::{extract_scan_targets, replace_scan_target, ScanTarget, TargetKind};
