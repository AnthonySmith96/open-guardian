use super::SecretError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

const PREFIX: &str = "{{secret:";
const SUFFIX: &str = "}}";
const MAX_REFERENCE_LENGTH: usize = 2048;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SecretRef {
    backend: String,
    path: String,
    field: Option<String>,
}

impl SecretRef {
    pub fn backend(&self) -> &str {
        &self.backend
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn field(&self) -> Option<&str> {
        self.field.as_deref()
    }
}

impl FromStr for SecretRef {
    type Err = SecretError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() > MAX_REFERENCE_LENGTH {
            return Err(invalid("reference is too long"));
        }
        let uri = input
            .strip_prefix(PREFIX)
            .and_then(|value| value.strip_suffix(SUFFIX))
            .ok_or_else(|| invalid("expected '{{secret:<backend>://<path>}}'"))?;
        if uri.contains("{{") || uri.contains("}}") {
            return Err(invalid("nested templates are not allowed"));
        }

        let (backend, location) = uri
            .split_once("://")
            .ok_or_else(|| invalid("backend scheme is missing"))?;
        if !is_valid_scheme(backend) {
            return Err(invalid("backend scheme is invalid"));
        }
        if location.contains("://") || location.contains('?') {
            return Err(invalid("nested schemes and query strings are not allowed"));
        }

        let mut parts = location.split('#');
        let path = parts.next().unwrap_or_default();
        let field = parts.next();
        if parts.next().is_some() {
            return Err(invalid("reference contains more than one field separator"));
        }
        validate_path(path)?;
        if let Some(field) = field {
            validate_field(field)?;
        }

        Ok(Self {
            backend: backend.to_string(),
            path: path.to_string(),
            field: field.map(str::to_string),
        })
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{PREFIX}{}://{}", self.backend, self.path)?;
        if let Some(field) = &self.field {
            write!(formatter, "#{field}")?;
        }
        formatter.write_str(SUFFIX)
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretRef")
            .field(&self.to_string())
            .finish()
    }
}

impl Serialize for SecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

pub(super) fn is_valid_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.count() <= 31
        && scheme
            .chars()
            .skip(1)
            .all(|character| matches!(character, 'a'..='z' | '0'..='9' | '_' | '-'))
}

fn validate_path(path: &str) -> Result<(), SecretError> {
    if path.is_empty() {
        return Err(invalid("path is empty"));
    }
    if path.starts_with('/') || path.ends_with('/') || path.contains('\\') {
        return Err(invalid("path must be logical and relative"));
    }
    if path
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(invalid("path contains whitespace or control characters"));
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(invalid("path contains an empty or traversal segment"));
    }
    Ok(())
}

fn validate_field(field: &str) -> Result<(), SecretError> {
    if field.is_empty()
        || !field.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
    {
        return Err(invalid("field is invalid"));
    }
    Ok(())
}

fn invalid(reason: &str) -> SecretError {
    SecretError::InvalidReference(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_round_trips_canonical_reference() {
        let raw = "{{secret:vault://infrastructure/proxmox#password}}";
        let reference: SecretRef = raw.parse().expect("valid reference");

        assert_eq!(reference.backend(), "vault");
        assert_eq!(reference.path(), "infrastructure/proxmox");
        assert_eq!(reference.field(), Some("password"));
        assert_eq!(reference.to_string(), raw);
    }

    #[test]
    fn serde_uses_a_single_string() {
        let reference: SecretRef = "{{secret:env://OPENAI_API_KEY}}"
            .parse()
            .expect("reference");
        let json = serde_json::to_string(&reference).expect("serialize");

        assert_eq!(json, r#""{{secret:env://OPENAI_API_KEY}}""#);
        assert_eq!(
            serde_json::from_str::<SecretRef>(&json).expect("deserialize"),
            reference
        );
    }

    #[test]
    fn rejects_traversal_nested_schemes_and_queries() {
        for invalid in [
            "{{secret:vault://../root#password}}",
            "{{secret:vault://service//key}}",
            "{{secret:vault://https://example.invalid/key}}",
            "{{secret:vault://service/key?version=1}}",
        ] {
            assert!(invalid.parse::<SecretRef>().is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn rejects_non_canonical_wrappers_and_schemes() {
        for invalid in [
            "secret:vault://service/key",
            " {{secret:vault://service/key}} ",
            "{{secret:Vault://service/key}}",
            "{{secret:vault://service/key#}}",
        ] {
            assert!(invalid.parse::<SecretRef>().is_err(), "accepted {invalid}");
        }
    }
}
