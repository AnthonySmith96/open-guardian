//! Strict, bounded plaintext contract for the portable vault prototype.
//!
//! This module does not perform file I/O or cryptography. Keeping payload
//! parsing separate makes the age boundary and the data-format boundary
//! independently testable.

#![allow(dead_code)] // Removed when the age-backed resolver is connected.

use super::{SecretError, SecretRef, SecretValue};
use chrono::DateTime;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::{HashMap, HashSet};
use std::fmt;
use zeroize::Zeroizing;

pub(super) const MAX_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 4_096;
const MAX_FIELDS_PER_ENTRY: usize = 64;
const MAX_TOTAL_FIELDS: usize = 16_384;
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_TOTAL_SECRET_BYTES: usize = 2 * 1024 * 1024;
const MAX_VAULT_ID_BYTES: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VaultPayloadV1 {
    format_version: u8,
    vault_id: String,
    generation: u64,
    created_at: String,
    updated_at: String,
    entries: Vec<VaultEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultEntry {
    logical_path: String,
    #[serde(deserialize_with = "deserialize_secret_fields")]
    fields: HashMap<String, VaultSecret>,
    created_at: String,
    updated_at: String,
}

struct VaultSecret(Zeroizing<String>);

impl<'de> Deserialize<'de> for VaultSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

fn deserialize_secret_fields<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, VaultSecret>, D::Error>
where
    D: Deserializer<'de>,
{
    struct SecretFieldsVisitor;

    impl<'de> Visitor<'de> for SecretFieldsVisitor {
        type Value = HashMap<String, VaultSecret>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object with unique secret field names")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let capacity = map.size_hint().unwrap_or(0).min(MAX_FIELDS_PER_ENTRY);
            let mut fields = HashMap::with_capacity(capacity);

            while let Some((name, value)) = map.next_entry::<String, VaultSecret>()? {
                if fields.len() >= MAX_FIELDS_PER_ENTRY {
                    return Err(de::Error::custom("too many fields in vault entry"));
                }
                if fields.insert(name, value).is_some() {
                    return Err(de::Error::custom("duplicate vault field"));
                }
            }

            Ok(fields)
        }
    }

    deserializer.deserialize_map(SecretFieldsVisitor)
}

impl VaultPayloadV1 {
    pub(super) fn parse(plaintext: &[u8]) -> Result<Self, SecretError> {
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(payload_error("plaintext size is outside the allowed range"));
        }

        let payload: Self =
            serde_json::from_slice(plaintext).map_err(|_| payload_error("payload is malformed"))?;
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<(), SecretError> {
        if self.format_version != 1 {
            return Err(payload_error("format version is unsupported"));
        }
        if self.vault_id.is_empty()
            || self.vault_id.len() > MAX_VAULT_ID_BYTES
            || !self.vault_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(payload_error("vault ID is invalid"));
        }
        validate_timestamp_pair(&self.created_at, &self.updated_at)?;
        if self.entries.len() > MAX_ENTRIES {
            return Err(payload_error("vault contains too many entries"));
        }

        let mut paths = HashSet::with_capacity(self.entries.len());
        let mut total_fields = 0_usize;
        let mut total_secret_bytes = 0_usize;

        for entry in &self.entries {
            if !paths.insert(entry.logical_path.as_str()) {
                return Err(payload_error("vault contains a duplicate logical path"));
            }
            validate_timestamp_pair(&entry.created_at, &entry.updated_at)?;
            if entry.fields.is_empty() || entry.fields.len() > MAX_FIELDS_PER_ENTRY {
                return Err(payload_error("vault entry field count is invalid"));
            }

            total_fields = total_fields.saturating_add(entry.fields.len());
            if total_fields > MAX_TOTAL_FIELDS {
                return Err(payload_error("vault contains too many fields"));
            }

            for (field, value) in &entry.fields {
                let reference = format!("{{{{secret:vault://{}#{}}}}}", entry.logical_path, field);
                reference
                    .parse::<SecretRef>()
                    .map_err(|_| payload_error("vault entry path or field is invalid"))?;
                if value.0.is_empty() || value.0.len() > MAX_SECRET_BYTES {
                    return Err(payload_error("vault secret size is invalid"));
                }
                total_secret_bytes = total_secret_bytes.saturating_add(value.0.len());
                if total_secret_bytes > MAX_TOTAL_SECRET_BYTES {
                    return Err(payload_error("vault secret data exceeds the allowed size"));
                }
            }
        }

        Ok(())
    }

    pub(super) fn into_secret(mut self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        if reference.backend() != "vault" {
            return Err(payload_error("backend received a non-vault reference"));
        }
        let field = reference
            .field()
            .ok_or_else(|| payload_error("vault references require a field"))?;
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.logical_path == reference.path())
            .ok_or_else(|| payload_error("vault entry or field is unavailable"))?;
        let value = entry
            .fields
            .remove(field)
            .ok_or_else(|| payload_error("vault entry or field is unavailable"))?;

        Ok(SecretValue(value.0))
    }

    #[allow(dead_code)]
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    #[allow(dead_code)]
    pub(super) fn vault_id(&self) -> &str {
        &self.vault_id
    }
}

fn validate_timestamp_pair(created_at: &str, updated_at: &str) -> Result<(), SecretError> {
    let created = DateTime::parse_from_rfc3339(created_at)
        .map_err(|_| payload_error("vault timestamp is invalid"))?;
    let updated = DateTime::parse_from_rfc3339(updated_at)
        .map_err(|_| payload_error("vault timestamp is invalid"))?;
    if updated < created {
        return Err(payload_error("vault timestamps are out of order"));
    }
    Ok(())
}

fn payload_error(reason: &str) -> SecretError {
    SecretError::Backend(format!("portable vault payload rejected: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_payload() -> &'static [u8] {
        br#"{
            "format_version": 1,
            "vault_id": "vault-01",
            "generation": 3,
            "created_at": "2026-07-18T10:00:00Z",
            "updated_at": "2026-07-18T11:00:00Z",
            "entries": [{
                "logical_path": "infrastructure/proxmox",
                "fields": {"password": "correct horse battery staple"},
                "created_at": "2026-07-18T10:00:00Z",
                "updated_at": "2026-07-18T11:00:00Z"
            }]
        }"#
    }

    #[test]
    fn parses_and_consumes_exact_secret_without_serializing_it() {
        let payload = VaultPayloadV1::parse(valid_payload()).expect("valid payload");
        let reference: SecretRef = "{{secret:vault://infrastructure/proxmox#password}}"
            .parse()
            .expect("reference");

        let value = payload.into_secret(&reference).expect("secret");

        assert_eq!(value.expose_secret(), "correct horse battery staple");
        assert_eq!(format!("{value:?}"), "SecretValue([REDACTED])");
    }

    #[test]
    fn rejects_duplicate_logical_paths() {
        let input = br#"{
            "format_version":1,"vault_id":"vault-01","generation":1,
            "created_at":"2026-07-18T10:00:00Z","updated_at":"2026-07-18T10:00:00Z",
            "entries":[
                {"logical_path":"same/path","fields":{"a":"one"},"created_at":"2026-07-18T10:00:00Z","updated_at":"2026-07-18T10:00:00Z"},
                {"logical_path":"same/path","fields":{"b":"two"},"created_at":"2026-07-18T10:00:00Z","updated_at":"2026-07-18T10:00:00Z"}
            ]
        }"#;

        assert!(VaultPayloadV1::parse(input).is_err());
    }

    #[test]
    fn rejects_duplicate_fields_before_resolution() {
        let input = br#"{
            "format_version":1,"vault_id":"vault-01","generation":1,
            "created_at":"2026-07-18T10:00:00Z","updated_at":"2026-07-18T10:00:00Z",
            "entries":[{"logical_path":"same/path","fields":{"password":"one","password":"two"},"created_at":"2026-07-18T10:00:00Z","updated_at":"2026-07-18T10:00:00Z"}]
        }"#;

        assert!(VaultPayloadV1::parse(input).is_err());
    }

    #[test]
    fn rejects_unknown_versions_fields_and_oversized_plaintext() {
        let wrong_version = String::from_utf8(valid_payload().to_vec())
            .expect("UTF-8")
            .replace("\"format_version\": 1", "\"format_version\": 2");
        let unknown_field = String::from_utf8(valid_payload().to_vec())
            .expect("UTF-8")
            .replace(
                "\"generation\": 3",
                "\"generation\": 3, \"unexpected\": true",
            );

        assert!(VaultPayloadV1::parse(wrong_version.as_bytes()).is_err());
        assert!(VaultPayloadV1::parse(unknown_field.as_bytes()).is_err());
        assert!(VaultPayloadV1::parse(&vec![b' '; MAX_PLAINTEXT_BYTES + 1]).is_err());
    }

    #[test]
    fn errors_never_include_secret_values() {
        let invalid = br#"{
            "format_version":1,"vault_id":"vault-01","generation":1,
            "created_at":"invalid-secret-value","updated_at":"2026-07-18T10:00:00Z",
            "entries":[]
        }"#;

        let error = match VaultPayloadV1::parse(invalid) {
            Ok(_) => panic!("invalid timestamp was accepted"),
            Err(error) => error,
        };

        assert!(!error.to_string().contains("invalid-secret-value"));
    }
}
