//! Read-only access to Open-Guardian's namespace in the native credential store.
//!
//! Administrative writes are intentionally kept out of `SecretBackend`: request
//! handling may resolve an explicit reference, but can never create, modify, or
//! enumerate credentials.

use super::{SecretBackend, SecretError, SecretRef, SecretValue};
use async_trait::async_trait;

/// Fixed service namespace prevents references from reaching credentials owned
/// by browsers, developer tools, or other applications.
pub const KEYCHAIN_SERVICE: &str = "io.github.anthonysmith96.open-guardian";

#[derive(Debug, Default)]
pub struct KeychainBackend;

impl KeychainBackend {
    fn account(reference: &SecretRef) -> Result<String, SecretError> {
        if reference.backend() != "keychain" {
            return Err(SecretError::Backend(
                "native keychain received a reference for another backend".to_string(),
            ));
        }

        let mut account = reference.path().to_string();
        if let Some(field) = reference.field() {
            account.push('#');
            account.push_str(field);
        }
        Ok(account)
    }
}

#[async_trait]
impl SecretBackend for KeychainBackend {
    fn scheme(&self) -> &'static str {
        "keychain"
    }

    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        let account = Self::account(reference)?;

        // Native credential-store calls can block on IPC or an OS authorization
        // prompt. Never occupy a Tokio worker while that happens.
        let value = tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &account).map_err(|_| {
                SecretError::Backend(
                    "native credential store is unavailable on this device".to_string(),
                )
            })?;
            entry.get_password().map_err(|_| {
                SecretError::Backend(
                    "requested Open-Guardian keychain entry is unavailable".to_string(),
                )
            })
        })
        .await
        .map_err(|_| SecretError::Backend("native credential-store worker failed".to_string()))??;

        SecretValue::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_maps_to_fixed_service_and_deterministic_account() {
        let reference: SecretRef = "{{secret:keychain://providers/openai#api_key}}"
            .parse()
            .expect("reference");

        assert_eq!(KEYCHAIN_SERVICE, "io.github.anthonysmith96.open-guardian");
        assert_eq!(
            KeychainBackend::account(&reference).expect("account"),
            "providers/openai#api_key"
        );
    }

    #[test]
    fn backend_rejects_reference_for_another_scheme() {
        let reference: SecretRef = "{{secret:env://OPENAI_API_KEY}}"
            .parse()
            .expect("reference");

        assert!(KeychainBackend::account(&reference).is_err());
    }
}
