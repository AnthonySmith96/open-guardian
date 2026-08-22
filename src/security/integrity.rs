//! HMAC Rule File Verification
//!
//! This module implements integrity verification for rule files using HMAC-SHA256.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub type HmacSignature = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleManifest {
    pub version: String,
    pub created_at: String,
    pub signatures: HashMap<String, String>,
    pub key_id: String,
}

#[derive(Debug, Clone)]
pub struct RuleVerificationResult {
    pub verified: bool,
    pub failed_files: Vec<FailedFile>,
}

#[derive(Debug, Clone)]
pub struct FailedFile {
    pub path: String,
    pub reason: String,
}

#[derive(Debug)]
pub enum IntegrityError {
    IoError(std::io::Error),
    ManifestParseError(String),
    FileNotFound(String),
}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityError::IoError(e) => write!(f, "IO error: {e}"),
            IntegrityError::ManifestParseError(e) => write!(f, "Manifest parse error: {e}"),
            IntegrityError::FileNotFound(p) => write!(f, "File not found: {p}"),
        }
    }
}

impl std::error::Error for IntegrityError {}

pub fn compute_file_hmac(path: &Path, key: &[u8]) -> Result<HmacSignature, IntegrityError> {
    let content = fs::read(path).map_err(IntegrityError::IoError)?;
    Ok(compute_hmac(&content, key))
}

pub fn compute_hmac(data: &[u8], key: &[u8]) -> HmacSignature {
    use hmac_sha256::HMAC;
    hex::encode(HMAC::mac(data, key))
}

pub fn verify_rule_file(
    path: &Path,
    expected_hmac: &str,
    key: &[u8],
) -> Result<bool, IntegrityError> {
    let actual_hmac = compute_file_hmac(path, key)?;
    Ok(actual_hmac == expected_hmac)
}

pub fn load_manifest(rules_dir: &Path) -> Result<RuleManifest, IntegrityError> {
    let manifest_path = rules_dir.join(".manifest.json");

    if !manifest_path.exists() {
        return Err(IntegrityError::FileNotFound(
            manifest_path.display().to_string(),
        ));
    }

    let content = fs::read_to_string(&manifest_path).map_err(IntegrityError::IoError)?;

    serde_json::from_str(&content).map_err(|e| IntegrityError::ManifestParseError(e.to_string()))
}

pub fn save_manifest(rules_dir: &Path, manifest: &RuleManifest) -> Result<(), IntegrityError> {
    let manifest_path = rules_dir.join(".manifest.json");
    let content = serde_json::to_string_pretty(manifest)
        .map_err(|e| IntegrityError::ManifestParseError(e.to_string()))?;
    fs::write(&manifest_path, content).map_err(IntegrityError::IoError)?;
    Ok(())
}

pub fn generate_manifest(rules_dir: &Path, key: &[u8]) -> Result<RuleManifest, IntegrityError> {
    let mut signatures = HashMap::new();

    let entries = fs::read_dir(rules_dir).map_err(IntegrityError::IoError)?;

    for entry in entries.flatten() {
        let path = entry.path();

        let is_rule_file = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("json") | Some("toml")
        ) && path
            .file_name()
            .map(|n| n != ".manifest.json")
            .unwrap_or(false);
        if is_rule_file {
            let hmac = compute_file_hmac(&path, key)?;
            let relative = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            signatures.insert(relative, hmac);
        }
    }

    Ok(RuleManifest {
        version: "1.0".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        signatures,
        key_id: "default".to_string(),
    })
}

pub fn verify_all_rules(
    rules_dir: &Path,
    manifest: &RuleManifest,
    key: &[u8],
) -> RuleVerificationResult {
    let mut failed_files = Vec::new();

    for (filename, expected_hmac) in &manifest.signatures {
        let rule_path = rules_dir.join(filename);

        if !rule_path.exists() {
            failed_files.push(FailedFile {
                path: filename.clone(),
                reason: "File not found".to_string(),
            });
            continue;
        }

        match verify_rule_file(&rule_path, expected_hmac, key) {
            Ok(true) => { /* OK */ }
            Ok(false) => {
                failed_files.push(FailedFile {
                    path: filename.clone(),
                    reason: "HMAC mismatch - file may have been tampered with".to_string(),
                });
                tracing::error!(
                    "SEC: Rule file integrity check FAILED for {}: HMAC mismatch",
                    filename
                );
            }
            Err(e) => {
                failed_files.push(FailedFile {
                    path: filename.clone(),
                    reason: format!("Verification error: {e}"),
                });
                tracing::error!("SEC: Rule file verification error for {}: {}", filename, e);
            }
        }
    }

    let verified = failed_files.is_empty();
    if verified {
        tracing::info!("SEC: All rule files verified successfully");
    } else {
        tracing::error!(
            "SEC: Rule file verification FAILED. {} files failed.",
            failed_files.len()
        );
    }

    RuleVerificationResult {
        verified,
        failed_files,
    }
}

pub struct RuleIntegrityChecker {
    rules_dir: PathBuf,
    key: Vec<u8>,
    manifest: Option<RuleManifest>,
}

impl RuleIntegrityChecker {
    pub fn new<P: AsRef<Path>>(rules_dir: P, hmac_key: &str) -> Result<Self, IntegrityError> {
        let rules_dir = rules_dir.as_ref().to_path_buf();
        let key = derive_key(hmac_key);
        let manifest = load_manifest(&rules_dir).ok();

        Ok(Self {
            rules_dir,
            key,
            manifest,
        })
    }

    pub fn verify(&self) -> RuleVerificationResult {
        match &self.manifest {
            Some(manifest) => verify_all_rules(&self.rules_dir, manifest, &self.key),
            None => {
                tracing::warn!("SEC: No rule manifest found - cannot verify integrity");

                RuleVerificationResult {
                    verified: false,
                    failed_files: vec![FailedFile {
                        path: "*".to_string(),
                        reason: "No manifest file found - rules not verified".to_string(),
                    }],
                }
            }
        }
    }

    pub fn generate_manifest(&self) -> Result<RuleManifest, IntegrityError> {
        generate_manifest(&self.rules_dir, &self.key)
    }

    pub fn save_manifest(&self) -> Result<(), IntegrityError> {
        let manifest = self.generate_manifest()?;
        save_manifest(&self.rules_dir, &manifest)
    }
}

fn derive_key(input: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}
