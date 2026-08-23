use crate::banner;
use open_guardian::secrets::{EnvironmentBackend, SecretRef};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Option<ServerConfig>,
    pub security: Option<SecurityConfig>,
    pub routes: Option<HashMap<String, RouteConfig>>,
    pub load_balancer: Option<LoadBalancerConfig>,
    pub vault: Option<VaultConfig>,
    pub broker: Option<BrokerConfig>,
}

/// Action Broker (v0.5) configuration. The daemon refuses to start unless
/// both `policy` and `public_key` resolve and the signature verifies.
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct BrokerConfig {
    /// Signed policy file (`policy.toml` + `policy.toml.sig`).
    pub policy: Option<String>,
    /// Pinned ed25519 public key (hex) for policy verification.
    pub public_key: Option<String>,
    /// Hash-chained audit log dedicated to the broker daemon.
    pub audit_log_path: Option<String>,
    /// Seconds a pending request waits for operator approval.
    pub pending_ttl_secs: Option<u64>,
    /// Seconds a finished result is retained (readable exactly once).
    pub result_ttl_secs: Option<u64>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind_address: Option<String>,
    pub port: Option<u16>,
    pub default_upstream: Option<String>,
    /// Per-client-IP request budget per minute. 0 disables the limiter.
    pub requests_per_minute: Option<u32>,
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    pub audit_log_path: Option<String>,
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

/// DLP configuration: enforcement action, rule files, and per-category
/// toggles. All detectors default to enabled.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct DlpConfig {
    /// "redact" (default) replaces sensitive data with reversible
    /// request-scoped placeholders; "block" rejects the request.
    #[serde(default = "DlpConfig::default_action")]
    pub action: String,
    /// Block requests whose sensitive data only surfaces after
    /// normalization/decoding (percent-encoded, HTML entities, ...).
    /// Such values cannot be safely rewritten in place, so the
    /// fail-closed default is to reject them.
    #[serde(default = "DlpConfig::default_block_on_obfuscated")]
    pub block_on_obfuscated: bool,
    /// gitleaks-compatible TOML files with secret detection rules.
    #[serde(default = "DlpConfig::default_rules_files")]
    pub rules_files: Vec<String>,
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
    fn default_action() -> String {
        "redact".to_string()
    }
    fn default_block_on_obfuscated() -> bool {
        true
    }
    fn default_rules_files() -> Vec<String> {
        vec!["rules/secrets.toml".to_string()]
    }

    pub fn email_enabled(&self) -> bool {
        self.email_redaction
    }
    pub fn cc_enabled(&self) -> bool {
        self.credit_card_redaction
    }
    pub fn ssn_enabled(&self) -> bool {
        self.ssn_redaction
    }
    pub fn ip_enabled(&self) -> bool {
        self.ip_redaction
    }
    pub fn phone_enabled(&self) -> bool {
        self.phone_redaction
    }
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            action: Self::default_action(),
            block_on_obfuscated: Self::default_block_on_obfuscated(),
            rules_files: Self::default_rules_files(),
            email_redaction: true,
            credit_card_redaction: true,
            secret_redaction: true,
            ssn_redaction: true,
            ip_redaction: true,
            phone_redaction: true,
        }
    }
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub url: String,
    pub model: Option<String>,
    pub credential: Option<SecretRef>,
    #[serde(default, rename = "key_env")]
    legacy_key_env: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    pub path: String,
    pub identity: SecretRef,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Semantic Load Balancer Config
// ─────────────────────────────────────────────────────────────────────────────

/// A single routing tier (fast or smart) in the Semantic Load Balancer.
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

fn make_resource_paths_absolute(config: &mut Config, config_path: &Path) {
    let Some(base_dir) = config_path.parent() else {
        return;
    };
    if let Some(dlp) = config
        .security
        .as_mut()
        .and_then(|security| security.dlp.as_mut())
    {
        for rules_file in &mut dlp.rules_files {
            let path = Path::new(&rules_file);
            if !path.is_absolute() {
                *rules_file = base_dir.join(path).to_string_lossy().into_owned();
            }
        }
    }

    if let Some(vault) = config.vault.as_mut() {
        let path = Path::new(&vault.path);
        if !path.is_absolute() {
            vault.path = base_dir.join(path).to_string_lossy().into_owned();
        }
    }

    if let Some(broker) = config.broker.as_mut() {
        for path in [&mut broker.policy, &mut broker.public_key]
            .into_iter()
            .flatten()
        {
            let candidate = Path::new(path);
            if !candidate.is_absolute() {
                *path = base_dir.join(candidate).to_string_lossy().into_owned();
            }
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
    if let Some(vault) = &config.vault {
        if vault.identity.backend() == "vault" {
            return Err(anyhow::anyhow!(
                "vault.identity cannot resolve from the vault it is intended to unlock"
            ));
        }
    }
    if let Some(server) = &config.server {
        if let Some(url) = &server.default_upstream {
            validate_endpoint(url, "server.default_upstream")?;
        }
    }
    if let Some(routes) = &config.routes {
        for (name, route) in routes {
            validate_endpoint(&route.url, &format!("routes.{name}.url"))?;
        }
    }
    if let Some(load_balancer) = &config.load_balancer {
        if load_balancer.enabled || !load_balancer.fast_tier.url.is_empty() {
            validate_endpoint(&load_balancer.fast_tier.url, "load_balancer.fast.url")?;
        }
        if load_balancer.enabled || !load_balancer.smart_tier.url.is_empty() {
            validate_endpoint(&load_balancer.smart_tier.url, "load_balancer.smart.url")?;
        }
    }
    if let Some(dlp) = config
        .security
        .as_ref()
        .and_then(|security| security.dlp.as_ref())
    {
        let action = dlp.action.to_lowercase();
        if !matches!(action.as_str(), "redact" | "block") {
            return Err(anyhow::anyhow!(
                "security.dlp.action must be \"redact\" or \"block\" (got {action:?})"
            ));
        }
    }
    Ok(())
}

fn validate_endpoint(raw: &str, location: &str) -> anyhow::Result<()> {
    let url =
        reqwest::Url::parse(raw).map_err(|_| anyhow::anyhow!("{location} is not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.cannot_be_a_base()
    {
        return Err(anyhow::anyhow!(
            "{location} must be an HTTP(S) base URL without userinfo, query, or fragment"
        ));
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
    make_resource_paths_absolute(&mut config, &path);
    normalize_credentials(&mut config)?;
    // stderr: stdout belongs to protocol-carrying subcommands (mcp,
    // mcp-gateway, sanitize) and must stay payload-only.
    eprintln!(" ✔ Loaded config from {}", path.display());
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::{make_resource_paths_absolute, normalize_credentials, Config};

    #[test]
    fn rules_file_paths_are_anchored_to_the_config_file() {
        let mut config: Config = toml::from_str(
            r#"
            [security.dlp]
            rules_files = ["rules/secrets.toml"]
            "#,
        )
        .expect("valid test config");
        let base = std::env::temp_dir().join("open-guardian-config-test");
        let config_path = base.join("guardian.toml");

        make_resource_paths_absolute(&mut config, &config_path);

        let dlp = config.security.expect("security").dlp.expect("dlp");
        assert_eq!(
            std::path::Path::new(&dlp.rules_files[0]),
            base.join("rules/secrets.toml")
        );
    }

    #[test]
    fn portable_vault_path_is_anchored_to_config_and_cannot_self_unlock() {
        let mut config: Config = toml::from_str(
            r#"
            [vault]
            path = "secrets/personal.guardian.age"
            identity = "{{secret:keychain://vaults/personal#age_identity}}"
            "#,
        )
        .expect("valid config");
        let base = std::env::temp_dir().join("open-guardian-vault-config-test");
        let config_path = base.join("guardian.toml");

        make_resource_paths_absolute(&mut config, &config_path);

        assert_eq!(
            std::path::Path::new(&config.vault.as_ref().expect("vault").path),
            base.join("secrets/personal.guardian.age")
        );
        normalize_credentials(&mut config).expect("non-circular identity");

        config.vault.as_mut().expect("vault").identity =
            "{{secret:vault://identity/device#private_key}}"
                .parse()
                .expect("reference");
        assert!(normalize_credentials(&mut config).is_err());
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
    fn unknown_fields_and_literal_route_keys_are_rejected() {
        let unknown_top_level = r#"
            [servre]
            port = 8080
        "#;
        let literal_route_key = r#"
            [routes]
            model = { url = "https://example.invalid/v1", api_key = "literal-secret" }
        "#;
        let removed_judge_section = r#"
            [judge]
            ai_judge_enabled = false
        "#;

        assert!(toml::from_str::<Config>(unknown_top_level).is_err());
        assert!(toml::from_str::<Config>(literal_route_key).is_err());
        assert!(
            toml::from_str::<Config>(removed_judge_section).is_err(),
            "v0.2 [judge] config must fail fast after the pivot, not linger silently"
        );
    }

    #[test]
    fn endpoint_urls_cannot_embed_credentials_or_query_secrets() {
        for url in [
            "https://user:password@example.invalid/v1",
            "https://example.invalid/v1?api_key=literal-secret",
            "file:///tmp/model.sock",
        ] {
            let mut config: Config = toml::from_str(&format!(
                r#"
                [routes]
                model = {{ url = "{url}" }}
                "#
            ))
            .expect("syntactically valid TOML");

            let error = normalize_credentials(&mut config).expect_err("unsafe URL accepted");
            assert!(!error.to_string().contains("literal-secret"));
            assert!(!error.to_string().contains("password"));
        }
    }

    #[test]
    fn invalid_dlp_action_is_rejected() {
        let mut config: Config = toml::from_str(
            r#"
            [security.dlp]
            action = "warn"
            "#,
        )
        .expect("valid TOML");

        assert!(normalize_credentials(&mut config).is_err());
    }

    #[test]
    fn default_dlp_config_redacts_and_blocks_obfuscated_secrets() {
        let config = super::DlpConfig::default();

        assert_eq!(config.action, "redact");
        assert!(config.block_on_obfuscated);
        assert_eq!(config.rules_files, vec!["rules/secrets.toml".to_string()]);
        assert!(config.secret_redaction);
    }

    #[test]
    fn distributed_profile_stays_local() {
        let config: Config = toml::from_str(include_str!("../guardian.toml"))
            .expect("distributed guardian.toml must parse");

        assert_eq!(
            config
                .server
                .as_ref()
                .and_then(|server| server.default_upstream.as_deref()),
            Some("http://127.0.0.1:11434/v1")
        );
        assert!(!config.load_balancer.expect("load balancer").enabled);
        assert_eq!(
            config.security.expect("security").dlp.expect("dlp").action,
            "redact"
        );
    }
}
