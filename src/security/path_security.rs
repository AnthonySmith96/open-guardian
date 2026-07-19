//! Path Canonicalization Module
//!
//! This module provides secure path handling to prevent path traversal attacks
//! by properly canonicalizing paths and validating them against allowlists.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathSecurityConfig {
    #[serde(default)]
    pub allowed_directories: Vec<PathBuf>,
    #[serde(default = "default_true")]
    pub resolve_symlinks: bool,
    #[serde(default = "default_false")]
    pub allow_absolute_paths: bool,
    #[serde(default = "default_true")]
    pub block_null_bytes: bool,
    #[serde(default = "default_max_depth")]
    pub max_path_depth: usize,
    #[serde(default)]
    pub allowed_extensions: Vec<String>,
    #[serde(default = "default_blocked_extensions")]
    pub blocked_extensions: Vec<String>,
}

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_max_depth() -> usize {
    20
}

fn default_blocked_extensions() -> Vec<String> {
    vec![
        "exe".to_string(),
        "dll".to_string(),
        "so".to_string(),
        "dylib".to_string(),
        "sh".to_string(),
        "bash".to_string(),
        "ps1".to_string(),
        "bat".to_string(),
        "cmd".to_string(),
    ]
}

impl Default for PathSecurityConfig {
    fn default() -> Self {
        Self {
            allowed_directories: Vec::new(),
            resolve_symlinks: true,
            allow_absolute_paths: false,
            block_null_bytes: true,
            max_path_depth: 20,
            allowed_extensions: Vec::new(),
            blocked_extensions: default_blocked_extensions(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathValidationResult {
    pub valid: bool,
    pub canonical_path: Option<PathBuf>,
    pub errors: Vec<PathValidationError>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PathValidationError {
    TraversalAttempt,
    OutsideAllowedDirectory,
    NullByteInjection,
    PathTooDeep,
    ExtensionNotAllowed,
    SymlinkEscapesAllowed,
    InvalidCharacters,
    AbsolutePathNotAllowed,
    FileNotFound,
}

pub struct PathSecurity {
    config: PathSecurityConfig,
    traversal_pattern: Regex,
    null_byte_pattern: Regex,
    url_encoded_traversal: Regex,
}

impl PathSecurity {
    pub fn new(config: PathSecurityConfig) -> Result<Self, regex::Error> {
        let traversal_pattern = Regex::new(r"(^|[/\\])\.\.([/\\]|$)")?;
        let null_byte_pattern = Regex::new(r"\x00")?;
        let url_encoded_traversal = Regex::new(r"(?i)(%2e%2e|%2e%2f|%2f%2e)")?;

        Ok(Self {
            config,
            traversal_pattern,
            null_byte_pattern,
            url_encoded_traversal,
        })
    }

    pub fn validate(&self, path: &str) -> PathValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        #[allow(unused_assignments)]
        let mut canonical_path: Option<PathBuf> = None;

        if self.config.block_null_bytes && self.null_byte_pattern.is_match(path) {
            errors.push(PathValidationError::NullByteInjection);
            return PathValidationResult {
                valid: false,
                canonical_path: None,
                errors,
                warnings,
            };
        }

        if self.url_encoded_traversal.is_match(path) {
            errors.push(PathValidationError::TraversalAttempt);
            return PathValidationResult {
                valid: false,
                canonical_path: None,
                errors,
                warnings,
            };
        }

        if self.traversal_pattern.is_match(path) {
            if !self.is_single_parent_ref_at_start(path) {
                errors.push(PathValidationError::TraversalAttempt);
            } else {
                warnings
                    .push("Path starts with '..' - verifying it resolves correctly".to_string());
            }
        }

        let path_obj = Path::new(path);

        if path_obj.is_absolute() && !self.config.allow_absolute_paths {
            errors.push(PathValidationError::AbsolutePathNotAllowed);
            return PathValidationResult {
                valid: false,
                canonical_path: None,
                errors,
                warnings,
            };
        }

        let depth = self.count_path_depth(path);
        if depth > self.config.max_path_depth {
            errors.push(PathValidationError::PathTooDeep);
            return PathValidationResult {
                valid: false,
                canonical_path: None,
                errors,
                warnings,
            };
        }

        let canonical = self.canonicalize_path(path_obj);

        match canonical {
            Ok(canonical_buf) => {
                if !self.is_within_allowed_directory(&canonical_buf) {
                    if self.config.allowed_directories.is_empty() {
                        warnings
                            .push("No allowed directories configured - bypass risk".to_string());
                    } else {
                        errors.push(PathValidationError::OutsideAllowedDirectory);
                    }
                } else {
                    debug!(
                        "Path {} resolved to {} (within allowed)",
                        path,
                        canonical_buf.display()
                    );
                }

                if let Some(ext) = canonical_buf.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();

                    if self
                        .config
                        .blocked_extensions
                        .iter()
                        .any(|b| b.to_lowercase() == ext_str)
                    {
                        errors.push(PathValidationError::ExtensionNotAllowed);
                    }

                    if !self.config.allowed_extensions.is_empty()
                        && !self
                            .config
                            .allowed_extensions
                            .iter()
                            .any(|a| a.to_lowercase() == ext_str)
                        && !self
                            .config
                            .blocked_extensions
                            .iter()
                            .any(|b| b.to_lowercase() == ext_str)
                    {
                        errors.push(PathValidationError::ExtensionNotAllowed);
                    }
                }

                canonical_path = Some(canonical_buf);
            }
            Err(e) => {
                warnings.push(format!("Failed to canonicalize path: {e}"));
                canonical_path = Some(path_obj.to_path_buf());
            }
        }

        let valid = errors.is_empty();

        PathValidationResult {
            valid,
            canonical_path,
            errors,
            warnings,
        }
    }

    fn is_single_parent_ref_at_start(&self, path: &str) -> bool {
        let trimmed = path.trim_start_matches('/').trim_start_matches('\\');
        trimmed == ".." || trimmed.starts_with("../") || trimmed.starts_with("..\\")
    }

    fn count_path_depth(&self, path: &str) -> usize {
        path.matches('/').count().max(path.matches('\\').count())
    }

    fn canonicalize_path(&self, path: &Path) -> Result<PathBuf, std::io::Error> {
        let normalized = self.normalize_path_components(path);

        if self.config.resolve_symlinks {
            fs::canonicalize(&normalized)
        } else {
            Ok(normalized)
        }
    }

    fn normalize_path_components(&self, path: &Path) -> PathBuf {
        let mut result = PathBuf::new();

        for component in path.components() {
            match component {
                std::path::Component::Normal(name) => {
                    result.push(name);
                }
                std::path::Component::ParentDir => {
                    if result.pop() {
                        debug!("Removed parent directory component");
                    }
                }
                std::path::Component::CurDir => {}
                std::path::Component::RootDir => {
                    result.push(component);
                }
                std::path::Component::Prefix(_) => {
                    result.push(component);
                }
            }
        }

        result
    }

    fn is_within_allowed_directory(&self, path: &Path) -> bool {
        if self.config.allowed_directories.is_empty() {
            return true;
        }

        let path_str = path.to_string_lossy().to_lowercase();

        for allowed in &self.config.allowed_directories {
            let allowed_str = allowed.to_string_lossy().to_lowercase();

            if path_str.starts_with(&allowed_str) {
                return true;
            }
        }

        false
    }

    pub fn add_allowed_directory(&mut self, dir: PathBuf) {
        self.config.allowed_directories.push(dir);
    }

    pub fn check_file_exists(&self, path: &Path) -> bool {
        path.exists() && path.is_file()
    }

    pub fn config(&self) -> &PathSecurityConfig {
        &self.config
    }
}

impl Default for PathSecurity {
    fn default() -> Self {
        Self::new(PathSecurityConfig::default()).unwrap()
    }
}

pub fn validate_path(path: &str) -> PathValidationResult {
    let security = PathSecurity::default();
    security.validate(path)
}

pub fn is_path_safe(path: &str) -> bool {
    let result = validate_path(path);
    result.valid && result.errors.is_empty()
}

pub fn sanitize_path(path: &str) -> String {
    let security = PathSecurity::default();
    let result = security.validate(path);

    result
        .canonical_path
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}
