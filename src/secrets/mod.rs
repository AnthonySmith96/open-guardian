//! Secret references and resolution live outside the model request pipeline.
//!
//! A `SecretRef` is safe to store, index, log, or send to a model because it
//! contains only an opaque location. A `SecretValue` is deliberately harder to
//! inspect and is zeroized when dropped.

mod reference;

use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroizing;

pub use reference::SecretRef;

/// Ephemeral secret material. It cannot be cloned and never prints its value.
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    pub fn new(value: String) -> Result<Self, SecretError> {
        if value.is_empty() {
            return Err(SecretError::EmptyValue);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    /// Deliberate escape hatch for the narrow transport/tool boundary.
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

#[derive(Debug)]
pub enum SecretError {
    InvalidReference(String),
    UnsupportedBackend(String),
    InvalidEnvironmentName,
    EnvironmentUnavailable(String),
    EmptyValue,
    Backend(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReference(reason) => {
                write!(formatter, "invalid secret reference: {reason}")
            }
            Self::UnsupportedBackend(backend) => {
                write!(formatter, "secret backend '{backend}' is not registered")
            }
            Self::InvalidEnvironmentName => {
                formatter.write_str("environment secret reference has an invalid variable name")
            }
            Self::EnvironmentUnavailable(name) => {
                write!(formatter, "environment credential '{name}' is unavailable")
            }
            Self::EmptyValue => formatter.write_str("resolved secret is empty"),
            Self::Backend(reason) => write!(formatter, "secret backend failed: {reason}"),
        }
    }
}

impl std::error::Error for SecretError {}

#[async_trait]
pub trait SecretBackend: Send + Sync {
    fn scheme(&self) -> &'static str;
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError>;
}

/// Deterministic backend registry. Models never receive a reference to it.
#[derive(Default)]
pub struct SecretBroker {
    backends: HashMap<String, Arc<dyn SecretBackend>>,
}

impl SecretBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<B>(&mut self, backend: B) -> Result<(), SecretError>
    where
        B: SecretBackend + 'static,
    {
        let scheme = backend.scheme();
        if !reference::is_valid_scheme(scheme) {
            return Err(SecretError::Backend(format!(
                "backend registered invalid scheme '{scheme}'"
            )));
        }
        if self.backends.contains_key(scheme) {
            return Err(SecretError::Backend(format!(
                "backend scheme '{scheme}' is already registered"
            )));
        }
        self.backends.insert(scheme.to_string(), Arc::new(backend));
        Ok(())
    }

    pub async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        let backend = self
            .backends
            .get(reference.backend())
            .ok_or_else(|| SecretError::UnsupportedBackend(reference.backend().to_string()))?;
        backend.resolve(reference).await
    }
}

/// Headless compatibility backend. Platform keychains and the portable vault
/// will implement the same trait without changing callers.
pub struct EnvironmentBackend;

impl EnvironmentBackend {
    pub fn reference(variable: &str) -> Result<SecretRef, SecretError> {
        if !is_valid_environment_name(variable) {
            return Err(SecretError::InvalidEnvironmentName);
        }
        format!("{{{{secret:env://{variable}}}}}").parse()
    }
}

#[async_trait]
impl SecretBackend for EnvironmentBackend {
    fn scheme(&self) -> &'static str {
        "env"
    }

    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        if reference.field().is_some() || !is_valid_environment_name(reference.path()) {
            return Err(SecretError::InvalidEnvironmentName);
        }

        let value = std::env::var(reference.path())
            .map_err(|_| SecretError::EnvironmentUnavailable(reference.path().to_string()))?;
        SecretValue::new(value)
    }
}

fn is_valid_environment_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('_' | 'A'..='Z' | 'a'..='z'))
        && chars.all(|character| matches!(character, '_' | 'A'..='Z' | 'a'..='z' | '0'..='9'))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedBackend;

    #[async_trait]
    impl SecretBackend for FixedBackend {
        fn scheme(&self) -> &'static str {
            "test"
        }

        async fn resolve(&self, _reference: &SecretRef) -> Result<SecretValue, SecretError> {
            SecretValue::new("sensitive-value".to_string())
        }
    }

    #[tokio::test]
    async fn broker_resolves_without_exposing_values_in_debug_output() {
        let mut broker = SecretBroker::new();
        broker.register(FixedBackend).expect("register backend");
        let reference: SecretRef = "{{secret:test://provider/key}}".parse().expect("reference");

        let value = broker.resolve(&reference).await.expect("resolve");

        assert_eq!(value.expose_secret(), "sensitive-value");
        assert_eq!(format!("{value:?}"), "SecretValue([REDACTED])");
    }

    #[tokio::test]
    async fn broker_rejects_unregistered_backends() {
        let broker = SecretBroker::new();
        let reference: SecretRef = "{{secret:vault://service/key}}".parse().expect("reference");

        assert!(matches!(
            broker.resolve(&reference).await,
            Err(SecretError::UnsupportedBackend(_))
        ));
    }

    #[test]
    fn environment_names_are_strict() {
        assert!(is_valid_environment_name("OPENAI_API_KEY"));
        assert!(!is_valid_environment_name("9INVALID"));
        assert!(!is_valid_environment_name("BAD-NAME"));
        assert!(!is_valid_environment_name(""));
    }
}
