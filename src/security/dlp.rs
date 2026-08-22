//! Data Loss Prevention engine.
//!
//! Two detector families share one engine:
//! - Built-in PII detectors (email, credit card with Luhn validation,
//!   phone, SSN, IPv4) with per-category toggles.
//! - External secret rules loaded from gitleaks-compatible TOML files
//!   (`rules/secrets.toml` by default), with keyword prefilters,
//!   Shannon-entropy gates, and secret-group scoping.
//!
//! Redaction happens through [`RedactionSession`], which mints
//! request-scoped reversible placeholders restored only after the
//! upstream response returns.

use crate::config::DlpConfig;
use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use serde::Deserialize;
use std::fmt;
use std::sync::OnceLock;
use zeroize::Zeroizing;

// ── Built-in PII patterns ──
static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
static CC_REGEX: OnceLock<Regex> = OnceLock::new();
static PHONE_REGEX: OnceLock<Regex> = OnceLock::new();
static IPV4_REGEX: OnceLock<Regex> = OnceLock::new();
static SSN_REGEX: OnceLock<Regex> = OnceLock::new();

/// DLP action policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DlpAction {
    /// Stop the request entirely if PII/secrets are found.
    Block,
    /// Replace sensitive data with anonymizer tokens and forward.
    Redact,
}

impl DlpAction {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "block" => DlpAction::Block,
            _ => DlpAction::Redact,
        }
    }
}

/// Violation details used for block-mode responses and audit events.
#[derive(Debug, Clone)]
pub struct DlpViolation {
    pub category: String,
    pub description: String,
}

// ── External rule loading (gitleaks-compatible subset) ──

#[derive(Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Deserialize)]
struct RawRule {
    id: String,
    #[serde(default)]
    description: Option<String>,
    regex: String,
    #[serde(rename = "secretGroup")]
    secret_group: Option<usize>,
    #[serde(default)]
    entropy: Option<f32>,
    #[serde(default)]
    keywords: Option<Vec<String>>,
}

/// A compiled secret-detection rule.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub description: Option<String>,
    pub regex: Regex,
    /// 1-based capture group redacted instead of the whole match.
    secret_group: Option<usize>,
    /// Minimum Shannon entropy (bits/char) required on the secret.
    entropy: Option<f32>,
    /// Lowercased prefilter: at least one must appear in the content.
    keywords: Vec<String>,
}

/// Errors loading or compiling the external rule set. Fatal at startup.
#[derive(Debug)]
pub enum DlpRuleError {
    Parse {
        path: String,
        source: toml::de::Error,
    },
    Compile {
        path: String,
        rule_id: String,
        source: regex::Error,
    },
    InvalidGroup {
        path: String,
        rule_id: String,
        group: usize,
        groups: usize,
    },
}

impl fmt::Display for DlpRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DlpRuleError::Parse { path, source } => {
                write!(f, "failed to parse rules file {path}: {source}")
            }
            DlpRuleError::Compile {
                path,
                rule_id,
                source,
            } => write!(f, "rule '{rule_id}' in {path} has an invalid regex: {source}"),
            DlpRuleError::InvalidGroup {
                path,
                rule_id,
                group,
                groups,
            } => write!(
                f,
                "rule '{rule_id}' in {path} references secretGroup {group} but only has {groups} capture groups"
            ),
        }
    }
}

impl std::error::Error for DlpRuleError {}

/// The shared detection engine: built once at startup, immutable afterwards.
pub struct DlpEngine {
    config: DlpConfig,
    rules: Vec<CompiledRule>,
}

impl fmt::Debug for DlpEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DlpEngine")
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl DlpEngine {
    /// Loads and compiles every configured rules file. Missing files warn
    /// and continue (built-in PII detectors stay active); malformed or
    /// uncompilable files are fatal — a broken rules file must never
    /// silently weaken protection.
    pub fn build(config: &DlpConfig) -> Result<Self, DlpRuleError> {
        let mut rules = Vec::new();
        for path in &config.rules_files {
            let resolved = crate::config::resolve_resource_path(path);
            let content = match std::fs::read_to_string(&resolved) {
                Ok(content) => content,
                Err(e) => {
                    banner_warning(&format!(
                        "DLP rules file {} not loaded ({e}); only built-in detectors are active",
                        resolved.display()
                    ));
                    continue;
                }
            };
            let parsed: RulesFile =
                toml::from_str(&content).map_err(|source| DlpRuleError::Parse {
                    path: resolved.display().to_string(),
                    source,
                })?;
            for raw in parsed.rules {
                rules.push(compile_rule(&raw, &resolved.display().to_string())?);
            }
        }
        tracing::info!(
            "DLP: {} external secret rule(s) loaded, {} rules file(s) configured",
            rules.len(),
            config.rules_files.len()
        );
        Ok(Self {
            config: config.clone(),
            rules,
        })
    }

    /// Test constructor with an empty external rule set.
    #[cfg(test)]
    pub fn builtin_only(config: &DlpConfig) -> Self {
        Self {
            config: config.clone(),
            rules: Vec::new(),
        }
    }

    /// Test constructor with explicitly provided rules.
    #[cfg(test)]
    fn with_rules(config: &DlpConfig, rules: Vec<CompiledRule>) -> Self {
        Self {
            config: config.clone(),
            rules,
        }
    }

    pub fn config(&self) -> &DlpConfig {
        &self.config
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// True if the content matches any active detector. `normalized`
    /// inputs (NFKC + casefolded + decoded) are also accepted so the
    /// caller can probe for obfuscated secrets.
    pub fn check_violations(&self, content: &str) -> Option<DlpViolation> {
        if self.config.secret_redaction {
            for rule in &self.rules {
                if rule_triggers(rule, content) {
                    return Some(DlpViolation {
                        category: "Secret".into(),
                        description: rule.description.clone().unwrap_or_else(|| rule.id.clone()),
                    });
                }
            }
        }

        let cfg = &self.config;
        if cfg.email_enabled() && email_re().is_match(content) {
            return Some(DlpViolation {
                category: "PII".into(),
                description: "Email address detected".into(),
            });
        }
        if cfg.ssn_enabled() && ssn_re().is_match(content) {
            return Some(DlpViolation {
                category: "PII".into(),
                description: "Social Security Number detected".into(),
            });
        }
        if cfg.cc_enabled() && contains_valid_card(content) {
            return Some(DlpViolation {
                category: "PII".into(),
                description: "Credit card number detected".into(),
            });
        }
        if cfg.phone_enabled() && phone_re().is_match(content) {
            return Some(DlpViolation {
                category: "PII".into(),
                description: "Phone number detected".into(),
            });
        }
        if cfg.ip_enabled() && ipv4_re().is_match(content) {
            return Some(DlpViolation {
                category: "PII".into(),
                description: "IPv4 address detected".into(),
            });
        }

        None
    }

    /// One-way redaction with opaque placeholders (`<EMAIL>`, `<RULE-ID>`),
    /// used on upstream response bodies where reversibility is not wanted.
    pub fn redact_permanent(&self, content: &str) -> String {
        let mut redacted = content.to_string();
        let cfg = &self.config;

        if cfg.secret_redaction {
            for rule in &self.rules {
                if keyword_prefilter_ok(rule, content) {
                    redacted = rule
                        .regex
                        .replace_all(&redacted, format!("<{}>", rule.id))
                        .into_owned();
                }
            }
        }
        if cfg.ssn_enabled() {
            redacted = ssn_re().replace_all(&redacted, "<SSN>").into_owned();
        }
        if cfg.email_enabled() {
            redacted = email_re().replace_all(&redacted, "<EMAIL>").into_owned();
        }
        if cfg.cc_enabled() {
            redacted = cc_re()
                .replace_all(&redacted, |captures: &regex::Captures<'_>| {
                    let candidate = &captures[0];
                    if luhn_valid(candidate) {
                        "<CC>".to_string()
                    } else {
                        candidate.to_string()
                    }
                })
                .into_owned();
        }
        if cfg.phone_enabled() {
            redacted = phone_re().replace_all(&redacted, "<PHONE>").into_owned();
        }
        if cfg.ip_enabled() {
            redacted = ipv4_re().replace_all(&redacted, "<IP>").into_owned();
        }

        redacted
    }

    /// Reversible redaction entry point used on request bodies.
    fn redact_session(&self, session: &mut RedactionSession, content: &str) -> String {
        let mut redacted = content.to_string();
        let cfg = &self.config;

        if cfg.secret_redaction {
            let lower = content.to_lowercase();
            for rule in &self.rules {
                if !rule.keywords.is_empty() && !rule.keywords.iter().any(|k| lower.contains(k)) {
                    continue;
                }
                redacted = rule
                    .regex
                    .replace_all(&redacted, |captures: &regex::Captures<'_>| {
                        secret_replacement(captures, rule, |value| session.store(value, &rule.id))
                    })
                    .into_owned();
            }
        }
        if cfg.ssn_enabled() {
            redacted = session.redact_matches(redacted, ssn_re(), "SSN");
        }
        if cfg.email_enabled() {
            redacted = session.redact_matches(redacted, email_re(), "EMAIL");
        }
        if cfg.cc_enabled() {
            redacted = cc_re()
                .replace_all(&redacted, |captures: &regex::Captures<'_>| {
                    let candidate = &captures[0];
                    if luhn_valid(candidate) {
                        session.store(candidate, "CC")
                    } else {
                        candidate.to_string()
                    }
                })
                .into_owned();
        }
        if cfg.phone_enabled() {
            redacted = session.redact_matches(redacted, phone_re(), "PHONE");
        }
        if cfg.ip_enabled() {
            redacted = session.redact_matches(redacted, ipv4_re(), "IP");
        }

        redacted
    }
}

fn banner_warning(message: &str) {
    // Kept as a function so unit tests never pull in the colored banner.
    crate::banner::print_warning(message);
}

fn compile_rule(raw: &RawRule, path: &str) -> Result<CompiledRule, DlpRuleError> {
    let regex = Regex::new(&raw.regex).map_err(|source| DlpRuleError::Compile {
        path: path.to_string(),
        rule_id: raw.id.clone(),
        source,
    })?;
    if let Some(group) = raw.secret_group {
        // captures_len includes group 0, so a valid group is < captures_len.
        if group == 0 || group >= regex.captures_len() {
            return Err(DlpRuleError::InvalidGroup {
                path: path.to_string(),
                rule_id: raw.id.clone(),
                group,
                groups: regex.captures_len().saturating_sub(1),
            });
        }
    }
    Ok(CompiledRule {
        id: raw.id.clone(),
        description: raw.description.clone(),
        regex,
        secret_group: raw.secret_group,
        entropy: raw.entropy,
        keywords: raw
            .keywords
            .as_ref()
            .map(|words| words.iter().map(|w| w.to_lowercase()).collect())
            .unwrap_or_default(),
    })
}

/// Detection-side trigger check: keyword prefilter + regex + entropy gate.
fn rule_triggers(rule: &CompiledRule, content: &str) -> bool {
    if !keyword_prefilter_ok(rule, content) {
        return false;
    }
    for captures in rule.regex.captures_iter(content) {
        if let Some(secret) = captures.get(rule.secret_group.unwrap_or(0)) {
            if entropy_ok(rule, secret.as_str()) {
                return true;
            }
        }
    }
    false
}

fn keyword_prefilter_ok(rule: &CompiledRule, content: &str) -> bool {
    rule.keywords.is_empty() || {
        let lower = content.to_lowercase();
        rule.keywords.iter().any(|k| lower.contains(k))
    }
}

fn entropy_ok(rule: &CompiledRule, secret: &str) -> bool {
    match rule.entropy {
        Some(min) => shannon_entropy(secret) >= f64::from(min),
        None => true,
    }
}

/// Builds the replacement for one rule match, honoring secretGroup
/// scoping and the entropy gate. Low-entropy matches are preserved
/// verbatim instead of being redacted.
fn secret_replacement(
    captures: &regex::Captures<'_>,
    rule: &CompiledRule,
    mut store: impl FnMut(&str) -> String,
) -> String {
    let group_index = rule.secret_group.unwrap_or(0);
    let secret = match captures.get(group_index) {
        Some(secret) if entropy_ok(rule, secret.as_str()) => secret,
        _ => return captures[0].to_string(),
    };

    // Preserve any context around the secret group (e.g. `api_key: `).
    match rule.secret_group {
        Some(_) => {
            let whole = captures.get(0).expect("group 0 always present");
            let relative_start = secret.start() - whole.start();
            let relative_end = secret.end() - whole.start();
            let whole_str = whole.as_str();
            format!(
                "{}{}{}",
                &whole_str[..relative_start],
                store(secret.as_str()),
                &whole_str[relative_end..]
            )
        }
        None => store(secret.as_str()),
    }
}

// ── Shannon entropy and Luhn validation ──

/// Shannon entropy in bits per character over the raw bytes.
fn shannon_entropy(value: &str) -> f64 {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let total = f64::from(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Luhn checksum validation for credit card candidates.
fn luhn_valid(candidate: &str) -> bool {
    let digits: Vec<u8> = candidate.bytes().filter(|b| b.is_ascii_digit()).collect();
    if digits.len() < 12 {
        return false;
    }
    let mut sum = 0u32;
    for (index, byte) in digits.iter().rev().enumerate() {
        let mut digit = u32::from(byte - b'0');
        if index % 2 == 1 {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    sum.is_multiple_of(10)
}

fn contains_valid_card(content: &str) -> bool {
    cc_re().find_iter(content).any(|m| luhn_valid(m.as_str()))
}

// ── Per-request reversible redaction ──

struct RedactedValue {
    token: String,
    value: Zeroizing<String>,
}

/// Per-request reversible redaction map. Values live only until the
/// upstream response is reconstructed and are zeroized when the session
/// is dropped.
pub struct RedactionSession {
    nonce: String,
    values: Vec<RedactedValue>,
}

impl RedactionSession {
    pub fn new() -> Self {
        let mut nonce = [0_u8; 16];
        OsRng.fill_bytes(&mut nonce);
        Self {
            nonce: hex::encode(nonce),
            values: Vec::new(),
        }
    }

    /// Replaces sensitive values with opaque, request-scoped tokens
    /// using every detector in the engine.
    pub fn redact(&mut self, content: &str, engine: &DlpEngine) -> String {
        engine.redact_session(self, content)
    }

    /// Restores only tokens minted by this request. Fabricated or replayed
    /// tokens from another request remain inert.
    pub fn restore(&self, content: &str) -> String {
        let mut restored = content.to_string();
        for entry in &self.values {
            restored = restored.replace(&entry.token, entry.value.as_str());
        }
        restored
    }

    pub fn redaction_count(&self) -> usize {
        self.values.len()
    }

    fn redact_matches(&mut self, input: String, pattern: &Regex, category: &str) -> String {
        pattern
            .replace_all(&input, |captures: &regex::Captures<'_>| {
                self.store(&captures[0], category)
            })
            .into_owned()
    }

    fn store(&mut self, value: &str, category: &str) -> String {
        let token = format!(
            "[[GUARDIAN_REDACTED:{}:{}:{}]]",
            self.nonce,
            self.values.len(),
            category
        );
        self.values.push(RedactedValue {
            token: token.clone(),
            value: Zeroizing::new(value.to_string()),
        });
        token
    }
}

impl Default for RedactionSession {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RedactionSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionSession")
            .field("redaction_count", &self.values.len())
            .finish_non_exhaustive()
    }
}

// ── Built-in detectors: compile lazily ──

fn email_re() -> &'static Regex {
    EMAIL_REGEX.get_or_init(|| Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap())
}
fn cc_re() -> &'static Regex {
    CC_REGEX.get_or_init(|| Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap())
}
fn phone_re() -> &'static Regex {
    PHONE_REGEX.get_or_init(|| {
        Regex::new(r"\b(?:\+?\d{1,3}[-. ]?)?\(?\d{2,4}\)?[-. ]?\d{3,4}[-. ]?\d{3,4}\b").unwrap()
    })
}
fn ipv4_re() -> &'static Regex {
    IPV4_REGEX.get_or_init(|| Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap())
}
fn ssn_re() -> &'static Regex {
    SSN_REGEX.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_rule(regex: &str) -> CompiledRule {
        compile_rule(
            &RawRule {
                id: "TEST-RULE".into(),
                description: Some("test rule".into()),
                regex: regex.into(),
                secret_group: None,
                entropy: None,
                keywords: None,
            },
            "test",
        )
        .expect("compile test rule")
    }

    #[test]
    fn luhn_rejects_digit_sequences_that_are_not_cards() {
        assert!(luhn_valid("4111-1111-1111-1111"));
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("1234-5678-9012-3456"));
    }

    #[test]
    fn card_redaction_requires_luhn_validity() {
        // Phone detection is disabled so the spaced digit sequence is only
        // judged by the credit card detector.
        let config = DlpConfig {
            phone_redaction: false,
            ..Default::default()
        };
        let engine = DlpEngine::builtin_only(&config);
        let mut session = RedactionSession::new();

        let invalid = "Card 1234-5678-9012-3456 stays";
        assert_eq!(session.redact(invalid, &engine), invalid);

        let redacted = session.redact("Card 4111-1111-1111-1111 gone", &engine);
        assert!(redacted.contains("GUARDIAN_REDACTED"));
        assert!(!redacted.contains("4111"));
    }

    #[test]
    fn block_mode_ignores_luhn_invalid_cards() {
        let config = DlpConfig {
            phone_redaction: false,
            ..Default::default()
        };
        let engine = DlpEngine::builtin_only(&config);
        assert!(engine
            .check_violations("Card 4111 1111 1111 1111")
            .is_some());
        assert!(engine
            .check_violations("Card 1234 5678 9012 3456")
            .is_none());
    }

    #[test]
    fn shannon_entropy_separates_random_from_repetitive() {
        assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0);
        assert!(shannon_entropy("f7Kq2#mZ9xLp4QRt") > 3.5);
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_gate_blocks_low_entropy_generic_secrets() {
        let mut raw = RawRule {
            id: "GEN".into(),
            description: None,
            regex: r#"(?i)api[_-]?key\s*[:=]\s*["']?([A-Za-z0-9]{16,})["']?"#.into(),
            secret_group: Some(1),
            entropy: Some(3.5),
            keywords: Some(vec!["api_key".into()]),
        };
        let rule = compile_rule(&raw, "test").expect("compiles");
        let engine = DlpEngine::with_rules(&DlpConfig::default(), vec![rule]);
        let mut session = RedactionSession::new();

        // Low-entropy value: preserved verbatim, no detection.
        let low = "api_key=aaaaaaaaaaaaaaaaaa";
        assert!(engine.check_violations(low).is_none());
        assert_eq!(session.redact(low, &engine), low);

        // High-entropy value: detected and redacted (only the group).
        raw.id = "GEN2".into();
        let rule2 = compile_rule(&raw, "test").expect("compiles");
        let engine2 = DlpEngine::with_rules(&DlpConfig::default(), vec![rule2]);
        let mut session2 = RedactionSession::new();
        let redacted = session2.redact("api_key=f7Kq2mZ9xLp4QRt8w2vB", &engine2);
        assert!(redacted.starts_with("api_key=[[GUARDIAN_REDACTED"));
        assert!(!redacted.contains("f7Kq2"));
    }

    #[test]
    fn keyword_prefilter_skips_unrelated_content() {
        let rule = compile_rule(
            &RawRule {
                id: "KW".into(),
                description: None,
                regex: r"[A-Z0-9]{16}".into(),
                secret_group: None,
                entropy: None,
                keywords: Some(vec!["AKIA".into()]),
            },
            "test",
        )
        .expect("compiles");
        let engine = DlpEngine::with_rules(&DlpConfig::default(), vec![rule]);

        assert!(engine
            .check_violations("totally unrelated ABCDEFGHIJKLMNOP text")
            .is_none());
        assert!(engine
            .check_violations("leaked AKIAIOSFODNN7EXAMPLE")
            .is_some());
    }

    #[test]
    fn rules_file_loads_and_detects() {
        let dir = std::env::temp_dir().join("open-guardian-dlp-rules-test");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("secrets.toml");
        let mut handle = std::fs::File::create(&file).expect("create rules file");
        writeln!(
            handle,
            r#"[[rules]]
id = "TESTFILE-KEY"
description = "test provider key"
regex = '\btpk_[A-Za-z0-9]{{20,}}\b'
keywords = ["tpk_"]
"#
        )
        .expect("write rules file");

        let config = DlpConfig {
            rules_files: vec![file.display().to_string()],
            ..Default::default()
        };
        let engine = DlpEngine::build(&config).expect("engine builds");
        assert_eq!(engine.rule_count(), 1);

        let mut session = RedactionSession::new();
        let redacted = session.redact("key tpk_abcdefghij1234567890 here", &engine);
        assert!(redacted.contains("TESTFILE-KEY"));
        assert!(!redacted.contains("tpk_abcdefghij"));
        assert_eq!(
            session.restore(&redacted),
            "key tpk_abcdefghij1234567890 here"
        );

        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn invalid_regex_is_a_fatal_build_error() {
        let dir = std::env::temp_dir().join("open-guardian-dlp-invalid-test");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("bad.toml");
        std::fs::write(
            &file,
            r#"[[rules]]
id = "BAD"
regex = '(?P<nested(unclosed'
"#,
        )
        .expect("write rules file");

        let config = DlpConfig {
            rules_files: vec![file.display().to_string()],
            ..Default::default()
        };
        let error = DlpEngine::build(&config).expect_err("must fail closed");
        assert!(error.to_string().contains("BAD"));

        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn secret_group_out_of_range_is_rejected() {
        let result = compile_rule(
            &RawRule {
                id: "GROUPED".into(),
                description: None,
                regex: "value: ([a-z]+)".into(),
                secret_group: Some(3),
                entropy: None,
                keywords: None,
            },
            "test",
        );
        assert!(result.is_err());
    }

    #[test]
    fn obfuscated_secret_is_detected_after_normalization() {
        // Percent-encoded OpenAI-style key: raw scan misses it, the
        // normalized probe (server-side) catches it via this engine.
        let engine = DlpEngine::build(&DlpConfig::default()).expect("engine builds");
        let obfuscated = "%73%6B%2Dabc123def456ghi789jklmnop";
        assert!(engine.check_violations(obfuscated).is_none());
        let normalized = crate::security::normalize_for_matching(obfuscated);
        assert!(engine.check_violations(&normalized).is_some());
    }

    #[test]
    fn secret_toggle_disables_external_rules() {
        let config = DlpConfig {
            secret_redaction: false,
            ..Default::default()
        };
        let engine = DlpEngine::with_rules(&config, vec![test_rule(r"\bAKIA[A-Z0-9]{16}\b")]);
        assert!(engine.check_violations("AKIAIOSFODNN7EXAMPLE").is_none());

        let mut session = RedactionSession::new();
        let text = "AKIAIOSFODNN7EXAMPLE";
        assert_eq!(session.redact(text, &engine), text);
    }

    #[test]
    fn permanent_redaction_uses_rule_ids() {
        let engine = DlpEngine::with_rules(
            &DlpConfig::default(),
            vec![test_rule(r"\bgsk_[A-Za-z0-9]{20,}\b")],
        );
        let redacted = engine.redact_permanent("key gsk_abcdefghijklmnopqrstuvwxyz");
        assert_eq!(redacted, "key <TEST-RULE>");
    }

    #[test]
    fn pii_redaction_round_trip() {
        let engine = DlpEngine::builtin_only(&DlpConfig::default());
        let mut session = RedactionSession::new();
        let input = "Connect to 192.168.1.100 as admin@example.com";

        let redacted = session.redact(input, &engine);

        assert!(!redacted.contains("192.168.1.100"));
        assert!(!redacted.contains("admin@example.com"));
        assert_eq!(session.redaction_count(), 2);
        assert_eq!(session.restore(&redacted), input);
    }

    #[test]
    fn session_does_not_restore_foreign_tokens() {
        let session = RedactionSession::new();
        let fabricated = "[[GUARDIAN_REDACTED:foreign:0:KEY]]";

        assert_eq!(session.restore(fabricated), fabricated);
    }

    #[test]
    fn session_debug_never_contains_values_or_nonce() {
        let engine = DlpEngine::builtin_only(&DlpConfig::default());
        let mut session = RedactionSession::new();
        let _ = session.redact("admin@example.com", &engine);
        let debug = format!("{session:?}");

        assert_eq!(debug, "RedactionSession { redaction_count: 1, .. }");
        assert!(!debug.contains("admin@example.com"));
    }
}
