use crate::banner;
use open_guardian::secrets::{EnvironmentBackend, SecretRef};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Debug, Default)]
pub struct Config {
    pub server: Option<ServerConfig>,
    pub security: Option<SecurityConfig>,
    pub judge: Option<JudgeConfig>,
    pub routes: Option<HashMap<String, RouteConfig>>,
    pub load_balancer: Option<LoadBalancerConfig>,
}

#[derive(Deserialize, Debug, Default)]
pub struct ServerConfig {
    pub bind_address: Option<String>,
    pub port: Option<u16>,
    pub default_upstream: Option<String>,
    pub requests_per_minute: Option<u32>,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct SecurityConfig {
    pub audit_log_path: Option<String>,
    pub block_threshold: Option<u32>,
    pub policies: Option<PolicyConfig>,
    pub dlp: Option<DlpConfig>,
    /// Whether to allow non-JSON requests to pass through (default: false for security)
    #[serde(default = "SecurityConfig::default_allow_non_json")]
    pub allow_non_json_passthrough: bool,
}

impl SecurityConfig {
    fn default_allow_non_json() -> bool {
        false // SECURITY: Default-deny non-JSON to prevent bypasses
    }
}

/// Per-category DLP toggle switches.
/// All default to `true` — disable specific categories as needed.
#[derive(Deserialize, Debug, Clone)]
pub struct DlpConfig {
    #[serde(default = "DlpConfig::default_true")]
    pub email_redaction: bool,
    #[serde(default = "DlpConfig::default_true")]
    pub credit_card_redaction: bool,
    #[serde(default = "DlpConfig::default_true")]
    pub secret_redaction: bool,
    #[serde(default = "DlpConfig::default_true")]
    pub ssn_redaction: bool,
    #[serde(default = "DlpConfig::default_true")]
    pub ip_redaction: bool,
    #[serde(default = "DlpConfig::default_true")]
    pub phone_redaction: bool,
}

impl DlpConfig {
    fn default_true() -> bool {
        true
    }
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            email_redaction: true,
            credit_card_redaction: true,
            secret_redaction: true,
            ssn_redaction: true,
            ip_redaction: true,
            phone_redaction: true,
        }
    }
}

/// A single dictionary source for threat signatures.
#[derive(Deserialize, Debug, Clone)]
pub struct DictionarySource {
    pub id: String,
    pub path: String,
    #[serde(default = "DictionarySource::default_enabled")]
    pub enabled: bool,
}

impl DictionarySource {
    fn default_enabled() -> bool {
        true
    }
}

/// Policy configuration: "Secure by Default, Configurable by Choice."
#[derive(Deserialize, Debug, Clone)]
pub struct PolicyConfig {
    /// Default action when a threat is detected: block, audit, redact, allow
    #[serde(default = "PolicyConfig::default_action")]
    pub default_action: String,

    /// DLP action: "block" or "redact"
    #[serde(default = "PolicyConfig::default_dlp_action")]
    pub dlp_action: String,

    /// Modular threat dictionaries (replaces old threats_path)
    #[serde(default = "PolicyConfig::default_dictionaries")]
    pub dictionaries: Vec<DictionarySource>,

    /// Whitelisted patterns (DevOps Mode) — these bypass the Threat Engine
    #[serde(default)]
    pub allowed_patterns: Vec<String>,
}

impl PolicyConfig {
    fn default_action() -> String {
        "audit".to_string()
    }
    fn default_dlp_action() -> String {
        "redact".to_string()
    }
    fn default_dictionaries() -> Vec<DictionarySource> {
        vec![
            DictionarySource {
                id: "common".into(),
                path: "rules/common.json".into(),
                enabled: true,
            },
            DictionarySource {
                id: "jailbreaks_en".into(),
                path: "rules/jailbreaks_en.json".into(),
                enabled: true,
            },
            DictionarySource {
                id: "jailbreaks_es".into(),
                path: "rules/jailbreaks_es.json".into(),
                enabled: true,
            },
        ]
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_action: Self::default_action(),
            dlp_action: Self::default_dlp_action(),
            dictionaries: Self::default_dictionaries(),
            allowed_patterns: Vec::new(),
        }
    }
}

/// Parsed policy action enum used at runtime.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PolicyAction {
    Block,
    Audit,
    Redact,
    Allow,
}

impl PolicyAction {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "audit" => PolicyAction::Audit,
            "redact" => PolicyAction::Redact,
            "allow" => PolicyAction::Allow,
            _ => PolicyAction::Block, // secure default
        }
    }
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct JudgeConfig {
    pub ai_judge_enabled: Option<bool>,
    pub ai_judge_endpoint: Option<String>,
    pub ai_judge_model: Option<String>,
    pub judge_cache_ttl_seconds: Option<u64>,
    pub judge_max_concurrency: Option<usize>,
    pub fail_open: Option<bool>,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct RouteConfig {
    pub url: String,
    pub model: Option<String>,
    pub credential: Option<SecretRef>,
    #[serde(default, rename = "key_env")]
    legacy_key_env: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Semantic Load Balancer Config
// ─────────────────────────────────────────────────────────────────────────────

/// A single routing tier (fast or smart) in the Semantic Load Balancer.
#[derive(Deserialize, Debug, Default, Clone)]
pub struct TierConfig {
    /// Upstream base URL for this tier.
    pub url: String,
    /// Optional model override to inject into the request body.
    pub model: Option<String>,
    /// Opaque reference resolved by SecretBroker only at the HTTP boundary.
    pub credential: Option<SecretRef>,
    #[serde(default, rename = "key_env")]
    legacy_key_env: Option<String>,
}

/// Configuration block for the Semantic Load Balancer (SLB).
/// Corresponds to `[load_balancer]` in guardian.toml.
#[derive(Deserialize, Debug, Default, Clone)]
pub struct LoadBalancerConfig {
    /// Master switch. Set to `false` to disable SLB entirely.
    #[serde(default)]
    pub enabled: bool,
    /// Complexity score threshold. Prompts scoring >= this go to `smart_tier`.
    /// Default: 40.
    pub smart_threshold: Option<u32>,
    /// Economy tier: low cost, high speed (e.g. Groq / Llama-3-8b).
    #[serde(default, rename = "fast")]
    pub fast_tier: TierConfig,
    /// Premium tier: high intelligence (e.g. GPT-4-Turbo / Claude Opus).
    #[serde(default, rename = "smart")]
    pub smart_tier: TierConfig,
}

fn executable_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
}

/// Resolves packaged resources next to the binary, with the current directory
/// as a development fallback. Absolute paths are never rewritten.
pub fn resolve_resource_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    if path.is_absolute() {
        return path.to_path_buf();
    }

    if let Some(candidate) = executable_dir().map(|base| base.join(path)) {
        if candidate.exists() {
            return candidate;
        }
    }

    std::env::current_dir().unwrap_or_default().join(path)
}

fn make_dictionary_paths_absolute(config: &mut Config, config_path: &Path) {
    let Some(base_dir) = config_path.parent() else {
        return;
    };
    let Some(policies) = config
        .security
        .as_mut()
        .and_then(|security| security.policies.as_mut())
    else {
        return;
    };

    for dictionary in &mut policies.dictionaries {
        let path = Path::new(&dictionary.path);
        if !path.is_absolute() {
            dictionary.path = base_dir.join(path).to_string_lossy().into_owned();
        }
    }
}

fn migrate_credential(
    credential: &mut Option<SecretRef>,
    legacy_key_env: &Option<String>,
    location: &str,
) -> anyhow::Result<()> {
    if credential.is_some() && legacy_key_env.is_some() {
        return Err(anyhow::anyhow!(
            "{location} defines both 'credential' and deprecated 'key_env'"
        ));
    }
    if credential.is_none() {
        if let Some(variable) = legacy_key_env {
            *credential = Some(EnvironmentBackend::reference(variable).map_err(|error| {
                anyhow::anyhow!("invalid deprecated key_env in {location}: {error}")
            })?);
            banner::print_warning(&format!(
                "{location}.key_env is deprecated; use credential = \"{{{{secret:env://{variable}}}}}\""
            ));
        }
    }
    Ok(())
}

fn normalize_credentials(config: &mut Config) -> anyhow::Result<()> {
    if let Some(routes) = config.routes.as_mut() {
        for (name, route) in routes {
            migrate_credential(
                &mut route.credential,
                &route.legacy_key_env,
                &format!("routes.{name}"),
            )?;
        }
    }
    if let Some(load_balancer) = config.load_balancer.as_mut() {
        migrate_credential(
            &mut load_balancer.fast_tier.credential,
            &load_balancer.fast_tier.legacy_key_env,
            "load_balancer.fast",
        )?;
        migrate_credential(
            &mut load_balancer.smart_tier.credential,
            &load_balancer.smart_tier.legacy_key_env,
            "load_balancer.smart",
        )?;
    }
    Ok(())
}

pub fn load_config() -> anyhow::Result<Config> {
    let explicit_path = std::env::var_os("GUARDIAN_CONFIG").map(PathBuf::from);
    let path = if let Some(path) = explicit_path {
        if !path.is_file() {
            return Err(anyhow::anyhow!(
                "GUARDIAN_CONFIG does not point to a readable file: {}",
                path.display()
            ));
        }
        Some(path)
    } else {
        executable_dir()
            .map(|base| base.join("guardian.toml"))
            .filter(|candidate| candidate.is_file())
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .map(|base| base.join("guardian.toml"))
                    .filter(|candidate| candidate.is_file())
            })
    };

    let Some(path) = path else {
        banner::print_warning("No guardian.toml found next to the binary or in the current directory. Using defaults.");
        return Ok(Config::default());
    };

    let content = fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {}", path.display(), error))?;
    let mut config = toml::from_str::<Config>(&content)
        .map_err(|error| anyhow::anyhow!("failed to parse {}: {}", path.display(), error))?;
    make_dictionary_paths_absolute(&mut config, &path);
    normalize_credentials(&mut config)?;
    banner::print_success(&format!("Loaded config from {}", path.display()));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::{make_dictionary_paths_absolute, normalize_credentials, Config};

    #[test]
    fn dictionary_paths_are_anchored_to_the_config_file() {
        let mut config: Config = toml::from_str(
            r#"
            [security.policies]
            [[security.policies.dictionaries]]
            id = "test"
            path = "rules/test.json"
            "#,
        )
        .expect("valid test config");
        let base = std::env::temp_dir().join("open-guardian-config-test");
        let config_path = base.join("guardian.toml");

        make_dictionary_paths_absolute(&mut config, &config_path);

        let dictionary = &config
            .security
            .expect("security")
            .policies
            .expect("policies")
            .dictionaries[0];
        assert_eq!(
            std::path::Path::new(&dictionary.path),
            base.join("rules/test.json")
        );
    }

    #[test]
    fn deprecated_key_env_is_migrated_to_a_secret_reference() {
        let mut config: Config = toml::from_str(
            r#"
            [routes]
            model = { url = "https://example.invalid/v1", key_env = "MODEL_API_KEY" }
            "#,
        )
        .expect("valid legacy config");

        normalize_credentials(&mut config).expect("migrate credential");

        let route = &config.routes.expect("routes")["model"];
        assert_eq!(
            route.credential.as_ref().expect("credential").to_string(),
            "{{secret:env://MODEL_API_KEY}}"
        );
    }

    #[test]
    fn duplicate_credential_configuration_is_rejected() {
        let mut config: Config = toml::from_str(
            r#"
            [routes]
            model = { url = "https://example.invalid/v1", key_env = "OLD_KEY", credential = "{{secret:env://NEW_KEY}}" }
            "#,
        )
        .expect("valid TOML");

        assert!(normalize_credentials(&mut config).is_err());
    }

    #[test]
    fn default_policy_observes_without_blocking_runbook_text() {
        assert_eq!(super::PolicyConfig::default().default_action, "audit");
        assert_eq!(
            super::PolicyAction::from_str("invalid-policy"),
            super::PolicyAction::Block
        );
    }
}
