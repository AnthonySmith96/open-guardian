//! Read-only age v1 portable-vault backend.

use super::vault_payload::{VaultPayloadV1, MAX_PLAINTEXT_BYTES};
use super::{SecretBackend, SecretError, SecretRef, SecretValue};
use async_trait::async_trait;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

const MAX_CIPHERTEXT_BYTES: usize = MAX_PLAINTEXT_BYTES + (4 * 1024 * 1024);

/// An age-encrypted vault bound to one device identity.
///
/// The backend is intentionally read-only. It has no API for initialization,
/// pairing, mutation, recovery, or recipient changes.
pub struct PortableVaultBackend {
    path: PathBuf,
    identity: Arc<SecretValue>,
}

impl PortableVaultBackend {
    pub fn new(path: impl AsRef<Path>, identity: SecretValue) -> Result<Self, SecretError> {
        identity
            .expose_secret()
            .parse::<age::x25519::Identity>()
            .map_err(|_| vault_error("device identity is invalid"))?;

        let path = std::fs::canonicalize(path)
            .map_err(|_| vault_error("encrypted vault file is unavailable"))?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| vault_error("encrypted vault filename is invalid"))?;
        if !file_name.ends_with(".guardian.age") {
            return Err(vault_error(
                "encrypted vault filename must end in .guardian.age",
            ));
        }
        let metadata = std::fs::metadata(&path)
            .map_err(|_| vault_error("encrypted vault file is unavailable"))?;
        if !metadata.is_file() || metadata.len() > MAX_CIPHERTEXT_BYTES as u64 {
            return Err(vault_error("encrypted vault file size is invalid"));
        }

        Ok(Self {
            path,
            identity: Arc::new(identity),
        })
    }

    fn resolve_sync(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        let identity = self
            .identity
            .expose_secret()
            .parse::<age::x25519::Identity>()
            .map_err(|_| vault_error("device identity is invalid"))?;
        let ciphertext = read_bounded_ciphertext(&self.path)?;
        let plaintext = age::decrypt(&identity, &ciphertext)
            .map(Zeroizing::new)
            .map_err(|_| vault_error("vault decryption failed"))?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(vault_error("decrypted payload exceeds the allowed size"));
        }

        VaultPayloadV1::parse(plaintext.as_slice())?.into_secret(reference)
    }
}

impl fmt::Debug for PortableVaultBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortableVaultBackend")
            .field("path", &self.path)
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
impl SecretBackend for PortableVaultBackend {
    fn scheme(&self) -> &'static str {
        "vault"
    }

    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        let path = self.path.clone();
        let identity = Arc::clone(&self.identity);
        let reference = reference.clone();

        tokio::task::spawn_blocking(move || Self { path, identity }.resolve_sync(&reference))
            .await
            .map_err(|_| vault_error("vault worker failed"))?
    }
}

fn read_bounded_ciphertext(path: &Path) -> Result<Vec<u8>, SecretError> {
    let file = File::open(path).map_err(|_| vault_error("encrypted vault file is unavailable"))?;
    let mut reader = file.take((MAX_CIPHERTEXT_BYTES + 1) as u64);
    let mut ciphertext = Vec::new();
    reader
        .read_to_end(&mut ciphertext)
        .map_err(|_| vault_error("encrypted vault file could not be read"))?;
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(vault_error("encrypted vault file exceeds the allowed size"));
    }
    Ok(ciphertext)
}

fn vault_error(reason: &str) -> SecretError {
    SecretError::Backend(format!("portable vault failed: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use rand::RngCore;

    const PAYLOAD: &[u8] = br#"{
        "format_version": 1,
        "vault_id": "vault-01",
        "generation": 3,
        "created_at": "2026-07-18T10:00:00Z",
        "updated_at": "2026-07-18T11:00:00Z",
        "entries": [{
            "logical_path": "infrastructure/proxmox",
            "fields": {"password": "portable-secret-value"},
            "created_at": "2026-07-18T10:00:00Z",
            "updated_at": "2026-07-18T11:00:00Z"
        }]
    }"#;

    struct TestVaultFile(PathBuf);

    impl TestVaultFile {
        fn encrypted_for(identity: &age::x25519::Identity) -> Self {
            let ciphertext = age::encrypt(&identity.to_public(), PAYLOAD).expect("encrypt fixture");
            let mut suffix = [0_u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut suffix);
            let path = std::env::temp_dir().join(format!(
                "open-guardian-{}.guardian.age",
                hex::encode(suffix)
            ));
            std::fs::write(&path, ciphertext).expect("write fixture");
            Self(path)
        }
    }

    impl Drop for TestVaultFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn secret_identity(identity: &age::x25519::Identity) -> SecretValue {
        SecretValue::new(identity.to_string().expose_secret().to_string()).expect("identity")
    }

    #[tokio::test]
    async fn decrypts_and_resolves_an_exact_field_through_broker() {
        let identity = age::x25519::Identity::generate();
        let file = TestVaultFile::encrypted_for(&identity);
        let backend =
            PortableVaultBackend::new(&file.0, secret_identity(&identity)).expect("vault backend");
        let mut broker = super::super::SecretBroker::new();
        broker.register(backend).expect("register vault");
        let reference: SecretRef = "{{secret:vault://infrastructure/proxmox#password}}"
            .parse()
            .expect("reference");

        let value = broker.resolve(&reference).await.expect("resolve");

        assert_eq!(value.expose_secret(), "portable-secret-value");
        assert_eq!(format!("{value:?}"), "SecretValue([REDACTED])");
    }

    #[tokio::test]
    async fn wrong_identity_fails_without_exposing_values() {
        let identity = age::x25519::Identity::generate();
        let wrong_identity = age::x25519::Identity::generate();
        let file = TestVaultFile::encrypted_for(&identity);
        let backend = PortableVaultBackend::new(&file.0, secret_identity(&wrong_identity))
            .expect("vault backend");
        let reference: SecretRef = "{{secret:vault://infrastructure/proxmox#password}}"
            .parse()
            .expect("reference");

        let error = backend
            .resolve(&reference)
            .await
            .expect_err("wrong identity");

        assert!(!error.to_string().contains("portable-secret-value"));
        assert!(!format!("{backend:?}").contains("AGE-SECRET-KEY"));
    }
}
