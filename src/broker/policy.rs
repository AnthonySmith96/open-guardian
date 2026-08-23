//! Signed action policies for the broker.
//!
//! A policy is a strict TOML file listing exactly which commands an agent may
//! request. It only takes effect with a valid detached ed25519 signature
//! (`<policy>.sig`) made by the key whose public half is pinned next to the
//! daemon. Verification is fail-closed: missing signature, wrong key, or one
//! flipped byte in the policy refuses to load.
//!
//! Signature file format (two lines):
//!
//! ```text
//! untrusted comment: open-guardian policy signature key=<key id>
//! <128 hex chars: ed25519 signature over the exact policy file bytes>
//! ```

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use open_guardian::secrets::SecretRef;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

pub const POLICY_VERSION: u32 = 1;
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// What the broker may do with a command's captured output.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutputPolicy {
    /// Run the output through the DLP engine (default): secrets and PII are
    /// replaced with one-way placeholders before anyone sees them.
    #[default]
    Redact,
    /// Never return output at all, regardless of content.
    Suppress,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    version: u32,
    #[serde(rename = "action")]
    actions: Vec<RawAction>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct RawAction {
    id: String,
    description: String,
    /// Literal argv. Never interpreted by a shell.
    exec: Vec<String>,
    /// sudo target user (Unix). `None` runs as the daemon's own user.
    #[serde(default)]
    user: Option<String>,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
    #[serde(default)]
    output: OutputPolicy,
    #[serde(default)]
    env: Vec<RawEnv>,
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct RawEnv {
    name: String,
    reference: SecretRef,
}

/// One allowlisted action, validated.
#[derive(Debug, Clone)]
pub struct ActionDef {
    pub id: String,
    pub description: String,
    pub exec: Vec<String>,
    pub user: Option<String>,
    pub timeout_secs: u64,
    pub output: OutputPolicy,
    pub env: Vec<EnvBinding>,
}

#[derive(Debug, Clone)]
pub struct EnvBinding {
    pub name: String,
    pub reference: SecretRef,
}

/// A fully verified policy.
#[derive(Debug, Clone)]
pub struct Policy {
    pub actions: Vec<ActionDef>,
    /// sha256 of the exact signed bytes, for audit records.
    pub fingerprint: String,
}

impl Policy {
    pub fn action(&self, id: &str) -> Option<&ActionDef> {
        self.actions.iter().find(|action| action.id == id)
    }
}

fn parse_and_validate(bytes: &str) -> Result<Vec<ActionDef>> {
    let raw: RawPolicy = toml::from_str(bytes).context("invalid policy TOML")?;
    if raw.version != POLICY_VERSION {
        anyhow::bail!(
            "unsupported policy version {} (expected {POLICY_VERSION})",
            raw.version
        );
    }

    let mut seen_ids = HashSet::new();
    for action in &raw.actions {
        if action.id.is_empty()
            || !action
                .id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            anyhow::bail!(
                "action id {:?} must be non-empty lowercase kebab-case",
                action.id
            );
        }
        if !seen_ids.insert(action.id.clone()) {
            anyhow::bail!("duplicate action id {:?}", action.id);
        }
        if action.description.trim().is_empty() {
            anyhow::bail!("action {:?} needs a description", action.id);
        }
        if action.exec.is_empty() || action.exec.iter().any(|part| part.is_empty()) {
            anyhow::bail!(
                "action {:?} exec must be a non-empty argv with no empty parts",
                action.id
            );
        }
        let program = &action.exec[0];
        if !Path::new(program).is_absolute() {
            anyhow::bail!(
                "action {:?} exec program must be an absolute path, got {:?}",
                action.id,
                program
            );
        }
        if let Some(user) = &action.user {
            if user.is_empty()
                || !user
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
            {
                anyhow::bail!(
                    "action {:?} user {:?} is not a plausible unix user name",
                    action.id,
                    user
                );
            }
        }
        if action.timeout_secs == 0 || action.timeout_secs > 600 {
            anyhow::bail!(
                "action {:?} timeout_secs must be between 1 and 600",
                action.id
            );
        }
        for binding in &action.env {
            if !is_valid_env_name(&binding.name) {
                anyhow::bail!(
                    "action {:?} env name {:?} is not a valid variable name",
                    action.id,
                    binding.name
                );
            }
        }
    }

    Ok(raw
        .actions
        .into_iter()
        .map(|action| ActionDef {
            id: action.id,
            description: action.description,
            exec: action.exec,
            user: action.user,
            timeout_secs: action.timeout_secs,
            output: action.output,
            env: action
                .env
                .into_iter()
                .map(|binding| EnvBinding {
                    name: binding.name,
                    reference: binding.reference,
                })
                .collect(),
        })
        .collect())
}

fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('_' | 'A'..='Z' | 'a'..='z'))
        && chars.all(|c| matches!(c, '_' | 'A'..='Z' | 'a'..='z' | '0'..='9'))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Keys and signatures
// ─────────────────────────────────────────────────────────────────────────────

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        anyhow::bail!("refusing to overwrite existing key {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        file.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes).with_context(|| format!("cannot create {}", path.display()))?;
    Ok(())
}

/// Short, stable identifier for a public key: first 16 hex of sha256.
pub fn key_id(verifying_key: &VerifyingKey) -> String {
    let digest = Sha256::digest(verifying_key.as_bytes());
    hex::encode(&digest[..8])
}

/// Generates an ed25519 keypair: `secret_path` (0600, hex seed) and
/// `secret_path.pub` (hex public key).
pub fn keygen(secret_path: &Path) -> Result<VerifyingKey> {
    // Seed from the process CSPRNG, then derive the key pair deterministically
    // (avoids pulling ed25519-dalek's rand_core 0.10 alongside our rand 0.8).
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    write_private(
        secret_path,
        format!("{}\n", hex::encode(signing_key.as_bytes())).as_bytes(),
    )?;
    let public_path = secret_path.with_extension("pub");
    if public_path == secret_path {
        anyhow::bail!("key path must have an extension for the .pub sibling");
    }
    std::fs::write(
        &public_path,
        format!("{}\n", hex::encode(signing_key.verifying_key().as_bytes())).as_bytes(),
    )
    .with_context(|| format!("cannot create {}", public_path.display()))?;
    Ok(signing_key.verifying_key())
}

fn read_hex_file(path: &Path, what: &str) -> Result<Vec<u8>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read {what} at {}", path.display()))?;
    let trimmed = content.trim();
    let bytes = hex::decode(trimmed).with_context(|| format!("{what} is not valid hex"))?;
    Ok(bytes)
}

fn load_verifying_key(public_key_path: &Path) -> Result<VerifyingKey> {
    let bytes = read_hex_file(public_key_path, "public key")?;
    let array: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("public key must be 32 bytes, got {}", bytes.len())
    })?;
    VerifyingKey::from_bytes(&array).context("invalid public key")
}

fn load_signing_key(secret_key_path: &Path) -> Result<SigningKey> {
    let bytes = read_hex_file(secret_key_path, "secret key")?;
    let array: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("secret key must be 32 bytes, got {}", bytes.len())
    })?;
    Ok(SigningKey::from_bytes(&array))
}

fn signature_path(policy_path: &Path) -> std::path::PathBuf {
    let mut name = policy_path.file_name().unwrap_or_default().to_os_string();
    name.push(".sig");
    policy_path.with_file_name(name)
}

/// Signs the exact bytes of the policy file and writes `<policy>.sig`.
pub fn sign_policy(policy_path: &Path, secret_key_path: &Path) -> Result<String> {
    let policy_bytes = std::fs::read(policy_path)
        .with_context(|| format!("cannot read policy {}", policy_path.display()))?;
    let signing_key = load_signing_key(secret_key_path)?;
    let signature: Signature = signing_key.sign(&policy_bytes);
    let sig_path = signature_path(policy_path);
    let content = format!(
        "untrusted comment: open-guardian policy signature key={}\n{}\n",
        key_id(&signing_key.verifying_key()),
        hex::encode(signature.to_bytes())
    );
    std::fs::write(&sig_path, content)
        .with_context(|| format!("cannot write {}", sig_path.display()))?;
    Ok(key_id(&signing_key.verifying_key()))
}

/// Verifies the signature without loading the policy structure.
pub fn verify_signature(policy_path: &Path, public_key_path: &Path) -> Result<String> {
    let policy_bytes = std::fs::read(policy_path)
        .with_context(|| format!("cannot read policy {}", policy_path.display()))?;
    let verifying_key = load_verifying_key(public_key_path)?;
    let sig_path = signature_path(policy_path);
    let sig_content = std::fs::read_to_string(&sig_path)
        .with_context(|| format!("missing signature {}", sig_path.display()))?;
    let sig_hex = sig_content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty() && !line.starts_with("untrusted comment:"))
        .context("signature file has no signature line")?;
    let sig_bytes = hex::decode(sig_hex.trim()).context("signature is not valid hex")?;
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("signature must be 64 bytes, got {}", bytes.len())
    })?;
    let signature = Signature::from_bytes(&sig_array);
    verifying_key
        .verify(&policy_bytes, &signature)
        .map_err(|_| anyhow::anyhow!("policy signature verification FAILED: policy file was modified or signed by another key"))?;
    Ok(key_id(&verifying_key))
}

/// Loads, verifies, and validates a policy. This is the daemon's only entry
/// point: every failure is fatal (fail-closed).
pub fn load_signed_policy(policy_path: &Path, public_key_path: &Path) -> Result<Policy> {
    let key_id = verify_signature(policy_path, public_key_path)?;
    let policy_bytes = std::fs::read(policy_path)?;
    let text = std::fs::read_to_string(policy_path)?;
    let actions = parse_and_validate(&text)?;
    let fingerprint = hex::encode(Sha256::digest(&policy_bytes));
    tracing::info!(
        "broker policy verified: key={key_id} fingerprint={fingerprint} actions={}",
        actions.len()
    );
    Ok(Policy {
        actions,
        fingerprint,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
//  sudoers generation
// ─────────────────────────────────────────────────────────────────────────────

/// Characters that would change sudoers matching semantics if they appeared
/// in an argv word; such actions cannot be expressed as an exact sudoers rule.
fn sudoers_safe(word: &str) -> bool {
    !word.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '*' | '?' | '[' | ']' | '\\' | '"' | '\'' | ',' | '#' | '!' | '=' | ':' | '(' | ')'
            )
    })
}

/// Renders one exact-match sudoers line per elevated action. The invoking user
/// is the OS user the broker daemon runs as.
pub fn sudoers_lines(policy: &Policy, invoking_user: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for action in &policy.actions {
        let Some(target) = &action.user else {
            continue;
        };
        if !action.exec.iter().all(|word| sudoers_safe(word)) {
            tracing::warn!(
                "action {} contains sudoers metacharacters; write its rule manually",
                action.id
            );
            continue;
        }
        lines.push(format!(
            "{invoking_user} ALL=({target}) NOPASSWD: {}",
            action.exec.join(" ")
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_policy() -> String {
        // Absolute programs so validation passes on every platform.
        let (echo, systemctl) = if cfg!(windows) {
            ("C:/Windows/System32/cmd.exe", "C:/Windows/System32/sc.exe")
        } else {
            ("/bin/echo", "/usr/bin/systemctl")
        };
        format!(
            r#"
version = 1

[[action]]
id = "echo-hello"
description = "Echo hello"
exec = ["{echo}", "hello"]

[[action]]
id = "restart-nginx"
description = "Restart nginx"
exec = ["{systemctl}", "restart", "nginx"]
user = "root"
timeout_secs = 30

[[action.env]]
name = "DEPLOY_TOKEN"
reference = "{{{{secret:env://DEPLOY_TOKEN}}}}"
"#
        )
    }

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("guardian-policy-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn signed_policy_dir(tag: &str) -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = TempDir::new(tag);
        let policy_path = dir.path("policy.toml");
        let key_path = dir.path("policy.key");
        std::fs::write(&policy_path, minimal_policy()).expect("write policy");
        keygen(&key_path).expect("keygen");
        sign_policy(&policy_path, &key_path).expect("sign");
        (dir, policy_path, key_path.with_extension("pub"))
    }

    #[test]
    fn signed_policy_loads_and_parses_actions() {
        let (_dir, policy_path, pub_path) = signed_policy_dir("ok");
        let policy = load_signed_policy(&policy_path, &pub_path).expect("loads");

        assert_eq!(policy.actions.len(), 2);
        let nginx = policy.action("restart-nginx").expect("nginx");
        assert_eq!(nginx.user.as_deref(), Some("root"));
        assert_eq!(nginx.env.len(), 1);
        assert_eq!(nginx.env[0].name, "DEPLOY_TOKEN");
        assert_eq!(nginx.output, OutputPolicy::Redact);
    }

    #[test]
    fn tampered_policy_is_rejected() {
        let (_dir, policy_path, pub_path) = signed_policy_dir("tamper");
        let original = std::fs::read_to_string(&policy_path).expect("read");
        // Add a brand-new action after signing.
        let tampered = original.replace(
            "[[action]]\nid = \"restart-nginx\"",
            "[[action]]\nid = \"wipe-disk\"\ndescription = \"Wipe\"\nexec = [\"/bin/rm\", \"-rf\", \"/\"]\n\n[[action]]\nid = \"restart-nginx\"",
        );
        assert_ne!(original, tampered);
        std::fs::write(&policy_path, tampered).expect("write tampered");

        let error = load_signed_policy(&policy_path, &pub_path).expect_err("must fail closed");
        assert!(error.to_string().contains("FAILED"));
    }

    #[test]
    fn missing_signature_is_rejected() {
        let dir = TempDir::new("nosig");
        let policy_path = dir.path("policy.toml");
        let key_path = dir.path("policy.key");
        std::fs::write(&policy_path, minimal_policy()).expect("write");
        keygen(&key_path).expect("keygen");
        // Never signed.

        let error = load_signed_policy(&policy_path, &key_path.with_extension("pub"))
            .expect_err("unsigned policy must not load");
        assert!(error.to_string().contains("missing signature"));
    }

    #[test]
    fn signature_from_another_key_is_rejected() {
        let (_dir, policy_path, _pub_path) = signed_policy_dir("wrongkey");
        let dir2 = TempDir::new("wrongkey2");
        let other_key = dir2.path("other.key");
        keygen(&other_key).expect("keygen");

        assert!(load_signed_policy(&policy_path, &other_key.with_extension("pub")).is_err());
    }

    #[test]
    fn invalid_policies_fail_validation() {
        let cases = [
            ("version", "version = 2\n[[action]]\nid = \"x\"\ndescription = \"d\"\nexec = [\"/bin/true\"]"),
            ("relative program", "version = 1\n[[action]]\nid = \"x\"\ndescription = \"d\"\nexec = [\"echo\", \"hi\"]"),
            ("duplicate id", "version = 1\n[[action]]\nid = \"x\"\ndescription = \"d\"\nexec = [\"/bin/true\"]\n[[action]]\nid = \"x\"\ndescription = \"d\"\nexec = [\"/bin/true\"]"),
            ("bad env name", "version = 1\n[[action]]\nid = \"x\"\ndescription = \"d\"\nexec = [\"/bin/true\"]\n[[action.env]]\nname = \"9BAD\"\nreference = \"{{secret:env://X}}\""),
            ("empty argv", "version = 1\n[[action]]\nid = \"x\"\ndescription = \"d\"\nexec = []"),
            ("bad timeout", "version = 1\n[[action]]\nid = \"x\"\ndescription = \"d\"\nexec = [\"/bin/true\"]\ntimeout_secs = 0"),
            ("unknown field", "version = 1\n[[action]]\nid = \"x\"\ndescription = \"d\"\nexec = [\"/bin/true\"]\nshell = true"),
            ("bad id", "version = 1\n[[action]]\nid = \"X Y\"\ndescription = \"d\"\nexec = [\"/bin/true\"]"),
        ];

        for (name, text) in cases {
            assert!(
                parse_and_validate(text).is_err(),
                "case {name:?} must be rejected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn sudoers_lines_are_exact_and_only_for_elevated_actions() {
        let (_dir, policy_path, pub_path) = signed_policy_dir("sudoers");
        let policy = load_signed_policy(&policy_path, &pub_path).expect("loads");

        let lines = sudoers_lines(&policy, "guardian-broker");
        assert_eq!(
            lines,
            vec!["guardian-broker ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx"]
        );
    }

    #[test]
    fn keygen_refuses_to_clobber_existing_keys() {
        let dir = TempDir::new("noclobber");
        let key = dir.path("k.key");
        std::fs::write(&key, "existing").expect("write");
        assert!(keygen(&key).is_err());
    }
}
