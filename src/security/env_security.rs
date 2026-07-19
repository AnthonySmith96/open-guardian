//! .env Security Hardening
//!
//! This module provides security hardening for environment file (.env) handling.

use serde::{Deserialize, Serialize};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_env_path() -> String {
    ".env".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSecurityConfig {
    #[serde(default = "default_env_path")]
    pub env_file_path: String,
    #[serde(default = "default_true")]
    pub warn_world_readable: bool,
    #[serde(default = "default_false")]
    pub block_insecure_env: bool,
    #[serde(default = "default_true")]
    pub check_ownership: bool,
    #[serde(default)]
    pub secret_store: SecretStore,
}

impl Default for EnvSecurityConfig {
    fn default() -> Self {
        Self {
            env_file_path: ".env".to_string(),
            warn_world_readable: true,
            block_insecure_env: false,
            check_ownership: true,
            secret_store: SecretStore::EnvironmentVariable,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub enum SecretStore {
    #[default]
    EnvironmentVariable,
    SystemdCreds,
    Vault,
    EnvFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSecurityResult {
    pub is_secure: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub permissions: Option<FilePermissions>,
    pub recommended_store: SecretStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePermissions {
    pub mode: u32,
    pub is_world_readable: bool,
    pub is_group_readable: bool,
    pub owner_uid: Option<u32>,
    pub group_gid: Option<u32>,
}

#[allow(unused_mut, unused_variables)]
pub fn check_env_security(env_path: &Path, config: &EnvSecurityConfig) -> EnvSecurityResult {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    let mut is_secure = true;
    let mut permissions = None;

    if !env_path.exists() {
        warnings
            .push("No .env file found - consider using environment variables instead".to_string());

        return EnvSecurityResult {
            is_secure: true,
            warnings,
            errors,
            permissions: None,
            recommended_store: SecretStore::EnvironmentVariable,
        };
    }

    match fs::metadata(env_path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                let mode = metadata.permissions().mode();
                let is_world_readable = (mode & 0o004) != 0;
                let is_group_readable = (mode & 0o040) != 0;

                let (owner_uid, group_gid) = {
                    use std::os::unix::fs::MetadataExt;
                    (Some(metadata.uid()), Some(metadata.gid()))
                };

                permissions = Some(FilePermissions {
                    mode,
                    is_world_readable,
                    is_group_readable,
                    owner_uid,
                    group_gid,
                });

                if config.warn_world_readable && is_world_readable {
                    let mode_str = format!("{mode:o}");
                    warnings.push(format!(
                        "INSECURE: .env file is world-readable (mode: {mode_str}). Anyone on the system can read your secrets!"
                    ));
                    warnings.push("RECOMMENDATION: Run: chmod 600 .env".to_string());

                    if config.block_insecure_env {
                        is_secure = false;
                        errors.push(
                            "World-readable .env file - startup blocked for security".to_string(),
                        );
                    }
                }

                if config.warn_world_readable && is_group_readable && !is_world_readable {
                    warnings.push(format!(
                        "WARNING: .env file is group-readable (mode: {mode:o}). Consider restricting to owner only."
                    ));
                }

                if config.check_ownership {
                    if let (Some(uid), Some(_gid)) = (owner_uid, group_gid) {
                        let current_uid = unsafe { libc::getuid() };

                        if uid == 0 {
                            // Owned by root - that's fine
                        } else if uid != current_uid {
                            warnings.push(format!(
                                "WARNING: .env file is owned by UID {uid}, not root or current user (UID {current_uid})"
                            ));
                        }
                    }
                }
            }

            #[cfg(not(unix))]
            {
                let _ = &metadata;
                tracing::warn!("SEC: .env permission checks are only available on Unix. Skipping.");
            }
        }
        Err(e) => {
            warnings.push(format!("Could not check .env permissions: {e}"));
        }
    }

    let recommended_store = if is_secure {
        determine_best_secret_store()
    } else {
        SecretStore::EnvironmentVariable
    };

    if !warnings.is_empty() {
        warnings.push(
            "RECOMMENDATION: Use environment variables instead of .env for production".to_string(),
        );
    }

    EnvSecurityResult {
        is_secure,
        warnings,
        errors,
        permissions,
        recommended_store,
    }
}

fn determine_best_secret_store() -> SecretStore {
    #[cfg(target_os = "linux")]
    {
        if std::env::var("INVOCATION_ID").is_ok() {
            return SecretStore::SystemdCreds;
        }
    }
    SecretStore::EnvironmentVariable
}

pub fn get_secret(env_var: &str) -> Option<String> {
    if let Ok(value) = std::env::var(env_var) {
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

pub fn validate_env_startup(base_dir: &Path) -> EnvSecurityResult {
    let config = EnvSecurityConfig::default();
    let env_path = base_dir.join(&config.env_file_path);

    let result = check_env_security(&env_path, &config);

    for warning in &result.warnings {
        tracing::warn!("SEC: .env security: {}", warning);
    }

    for error in &result.errors {
        tracing::error!("SEC: .env security ERROR: {}", error);
    }

    result
}
