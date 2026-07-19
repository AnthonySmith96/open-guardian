use crate::config::DlpConfig;
use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use std::fmt;
use std::sync::OnceLock;
use zeroize::Zeroizing;

// ── PII Patterns ──
static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
static CC_REGEX: OnceLock<Regex> = OnceLock::new();
static PHONE_REGEX: OnceLock<Regex> = OnceLock::new();
static IPV4_REGEX: OnceLock<Regex> = OnceLock::new();
static SSN_REGEX: OnceLock<Regex> = OnceLock::new();

// ── Secret/Credential Patterns ──
static AWS_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static GITHUB_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
static OPENAI_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static OPENAI_PROJ_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static GROQ_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
static SLACK_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
static GENERIC_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
static BEARER_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();

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

/// Violation details when DLP action is Block.
#[derive(Debug, Clone)]
pub struct DlpViolation {
    pub category: String,
    pub description: String,
}

struct RedactedValue {
    token: String,
    value: Zeroizing<String>,
}

/// Per-request reversible redaction map. Values live only until the upstream
/// response is reconstructed and are zeroized when the session is dropped.
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

    /// Replaces sensitive values with opaque, request-scoped tokens.
    pub fn redact(&mut self, content: &str, config: Option<&DlpConfig>) -> String {
        let mut redacted = content.to_string();
        let secret_enabled = config.map(|c| c.secret_redaction).unwrap_or(true);
        let email_enabled = config.map(|c| c.email_redaction).unwrap_or(true);
        let ssn_enabled = config.map(|c| c.ssn_redaction).unwrap_or(true);
        let cc_enabled = config.map(|c| c.credit_card_redaction).unwrap_or(true);
        let phone_enabled = config.map(|c| c.phone_redaction).unwrap_or(true);
        let ip_enabled = config.map(|c| c.ip_redaction).unwrap_or(true);

        if secret_enabled {
            redacted = self.redact_matches(redacted, openai_proj_re(), "KEY");
            redacted = self.redact_matches(redacted, aws_re(), "AWS_KEY");
            redacted = self.redact_matches(redacted, github_re(), "GITHUB_TOKEN");
            redacted = self.redact_matches(redacted, openai_re(), "KEY");
            redacted = self.redact_matches(redacted, groq_re(), "KEY");
            redacted = self.redact_matches(redacted, slack_re(), "SLACK_TOKEN");
            redacted = self.redact_matches(redacted, generic_re(), "SECRET");
            redacted = self.redact_matches(redacted, bearer_re(), "BEARER");
        }
        if ssn_enabled {
            redacted = self.redact_matches(redacted, ssn_re(), "SSN");
        }
        if email_enabled {
            redacted = self.redact_matches(redacted, email_re(), "EMAIL");
        }
        if cc_enabled {
            redacted = self.redact_matches(redacted, cc_re(), "CC");
        }
        if phone_enabled {
            redacted = self.redact_matches(redacted, phone_re(), "PHONE");
        }
        if ip_enabled {
            redacted = self.redact_matches(redacted, ipv4_re(), "IP");
        }

        redacted
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

// ── Helper: compile all regex patterns lazily ──

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
fn aws_re() -> &'static Regex {
    AWS_KEY_REGEX.get_or_init(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap())
}
fn github_re() -> &'static Regex {
    GITHUB_TOKEN_REGEX.get_or_init(|| Regex::new(r"\b(gh[pous]_[a-zA-Z0-9]{36})\b").unwrap())
}
fn openai_re() -> &'static Regex {
    OPENAI_KEY_REGEX.get_or_init(|| Regex::new(r"\bsk-[a-zA-Z0-9]{20,}\b").unwrap())
}
fn openai_proj_re() -> &'static Regex {
    OPENAI_PROJ_KEY_REGEX.get_or_init(|| Regex::new(r"\bsk-proj-[a-zA-Z0-9_-]{20,}\b").unwrap())
}
fn groq_re() -> &'static Regex {
    GROQ_KEY_REGEX.get_or_init(|| Regex::new(r"\bgsk_[a-zA-Z0-9]{20,}\b").unwrap())
}
fn slack_re() -> &'static Regex {
    SLACK_TOKEN_REGEX.get_or_init(|| Regex::new(r"\bxox[bpsa]-[a-zA-Z0-9-]{10,}\b").unwrap())
}
fn generic_re() -> &'static Regex {
    GENERIC_SECRET_REGEX.get_or_init(|| Regex::new(r#"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#).unwrap())
}
fn bearer_re() -> &'static Regex {
    BEARER_TOKEN_REGEX.get_or_init(|| Regex::new(r#"Bearer\s+[a-zA-Z0-9_\-\.]{20,}"#).unwrap())
}

/// Check if content contains any PII or secrets, returning a violation if found.
/// Used when DLP action is set to "block".
///
/// Respects per-category toggles in DlpConfig if provided.
pub fn check_for_violations(content: &str, config: Option<&DlpConfig>) -> Option<DlpViolation> {
    let secret_enabled = config.map(|c| c.secret_redaction).unwrap_or(true);
    let email_enabled = config.map(|c| c.email_redaction).unwrap_or(true);
    let ssn_enabled = config.map(|c| c.ssn_redaction).unwrap_or(true);
    let cc_enabled = config.map(|c| c.credit_card_redaction).unwrap_or(true);

    // Secrets first (more specific)
    if secret_enabled {
        if openai_proj_re().is_match(content) {
            return Some(DlpViolation {
                category: "Secret".into(),
                description: "OpenAI project key detected (sk-proj-)".into(),
            });
        }
        if aws_re().is_match(content) {
            return Some(DlpViolation {
                category: "Secret".into(),
                description: "AWS access key detected".into(),
            });
        }
        if github_re().is_match(content) {
            return Some(DlpViolation {
                category: "Secret".into(),
                description: "GitHub token detected (ghp_/gho_/ghs_/ghu_)".into(),
            });
        }
        if openai_re().is_match(content) {
            return Some(DlpViolation {
                category: "Secret".into(),
                description: "OpenAI API key detected (sk-)".into(),
            });
        }
        if groq_re().is_match(content) {
            return Some(DlpViolation {
                category: "Secret".into(),
                description: "Groq API key detected (gsk_)".into(),
            });
        }
        if slack_re().is_match(content) {
            return Some(DlpViolation {
                category: "Secret".into(),
                description: "Slack token detected (xoxb-/xoxp-)".into(),
            });
        }
    }

    // PII
    if email_enabled && email_re().is_match(content) {
        return Some(DlpViolation {
            category: "PII".into(),
            description: "Email address detected".into(),
        });
    }
    if ssn_enabled && ssn_re().is_match(content) {
        return Some(DlpViolation {
            category: "PII".into(),
            description: "Social Security Number detected".into(),
        });
    }
    if cc_enabled && cc_re().is_match(content) {
        return Some(DlpViolation {
            category: "PII".into(),
            description: "Credit card number detected".into(),
        });
    }

    None
}

/// Redact PII and secrets from content, replacing with context-preserving
/// anonymizer tokens (e.g. `<EMAIL>`, `<KEY>`) instead of opaque `[REDACTED]`.
///
/// This preserves semantic context for AI Agents while neutralizing the data.
/// Respects per-category toggles in DlpConfig if provided.
pub fn redact_pii(content: &str, config: Option<&DlpConfig>) -> String {
    let mut redacted = content.to_string();

    let secret_enabled = config.map(|c| c.secret_redaction).unwrap_or(true);
    let email_enabled = config.map(|c| c.email_redaction).unwrap_or(true);
    let ssn_enabled = config.map(|c| c.ssn_redaction).unwrap_or(true);
    let cc_enabled = config.map(|c| c.credit_card_redaction).unwrap_or(true);
    let phone_enabled = config.map(|c| c.phone_redaction).unwrap_or(true);
    let ip_enabled = config.map(|c| c.ip_redaction).unwrap_or(true);

    // Apply redactions in order: more specific secrets first, then generic, then PII
    if secret_enabled {
        redacted = openai_proj_re().replace_all(&redacted, "<KEY>").to_string();
        redacted = aws_re().replace_all(&redacted, "<AWS_KEY>").to_string();
        redacted = github_re()
            .replace_all(&redacted, "<GITHUB_TOKEN>")
            .to_string();
        redacted = openai_re().replace_all(&redacted, "<KEY>").to_string();
        redacted = groq_re().replace_all(&redacted, "<KEY>").to_string();
        redacted = slack_re()
            .replace_all(&redacted, "<SLACK_TOKEN>")
            .to_string();
        redacted = generic_re().replace_all(&redacted, "<SECRET>").to_string();
        redacted = bearer_re().replace_all(&redacted, "<BEARER>").to_string();
    }

    // PII
    if ssn_enabled {
        redacted = ssn_re().replace_all(&redacted, "<SSN>").to_string();
    }
    if email_enabled {
        redacted = email_re().replace_all(&redacted, "<EMAIL>").to_string();
    }
    if cc_enabled {
        redacted = cc_re().replace_all(&redacted, "<CC>").to_string();
    }
    if phone_enabled {
        redacted = phone_re().replace_all(&redacted, "<PHONE>").to_string();
    }
    if ip_enabled {
        redacted = ipv4_re().replace_all(&redacted, "<IP>").to_string();
    }

    redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_redaction() {
        let input = "Send an email to john.doe@example.com for info.";
        let expected = "Send an email to <EMAIL> for info.";
        assert_eq!(redact_pii(input, None), expected);
    }

    #[test]
    fn test_cc_redaction() {
        let input = "My card number is 1234-5678-9012-3456.";
        let expected = "My card number is <CC>.";
        assert_eq!(redact_pii(input, None), expected);
    }

    #[test]
    fn test_ssn_redaction() {
        let input = "My SSN is 123-45-6789 please process.";
        let expected = "My SSN is <SSN> please process.";
        assert_eq!(redact_pii(input, None), expected);
    }

    #[test]
    fn test_openai_key_redaction() {
        let input = "My key is sk-abc123def456ghi789jklmnop and it works.";
        let expected = "My key is <KEY> and it works.";
        assert_eq!(redact_pii(input, None), expected);
    }

    #[test]
    fn test_openai_proj_key_redaction() {
        let input = "Use sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef to connect.";
        let expected = "Use <KEY> to connect.";
        assert_eq!(redact_pii(input, None), expected);
    }

    #[test]
    fn test_aws_key_redaction() {
        let input = "Use key AKIAIOSFODNN7EXAMPLE for AWS.";
        let expected = "Use key <AWS_KEY> for AWS.";
        assert_eq!(redact_pii(input, None), expected);
    }

    #[test]
    fn test_github_token_redaction() {
        let input = "Token: ghp_abcdefghijklmnopqrstuvwxyz1234567890 works.";
        let expected = "Token: <GITHUB_TOKEN> works.";
        assert_eq!(redact_pii(input, None), expected);
    }

    #[test]
    fn test_slack_token_redaction() {
        let input = "Bot token: xoxb-123456789-abcdefghij for the bot.";
        let expected = "Bot token: <SLACK_TOKEN> for the bot.";
        assert_eq!(redact_pii(input, None), expected);
    }

    #[test]
    fn test_groq_key_redaction() {
        let input = "Groq key is gsk_abcdefghijklmnopqrstuvwxyz.";
        let expected = "Groq key is <KEY>.";
        assert_eq!(redact_pii(input, None), expected);
    }

    #[test]
    fn test_ipv4_redaction() {
        let input = "Server is at 192.168.1.100 on the network.";
        let expected = "Server is at <IP> on the network.";
        assert_eq!(redact_pii(input, None), expected);
    }

    #[test]
    fn test_check_violations_blocks_email() {
        let result = check_for_violations("Contact me at admin@secret.com", None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().category, "PII");
    }

    #[test]
    fn test_check_violations_blocks_sk_proj() {
        let result = check_for_violations("Here is sk-proj-abcdef1234567890abcdef1234567890", None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().category, "Secret");
    }

    #[test]
    fn test_check_violations_blocks_slack() {
        let result = check_for_violations("Use xoxb-1234567890-abcdefgh to connect", None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().category, "Secret");
    }

    #[test]
    fn test_clean_content_passes() {
        let result = check_for_violations("Tell me a joke about cats.", None);
        assert!(result.is_none());
    }

    #[test]
    fn test_redaction_toggles() {
        let input = "Email: test@test.com, Key: sk-1234567890abcdefghij";
        let config = DlpConfig {
            email_redaction: false,
            secret_redaction: true,
            ..Default::default()
        };
        let result = redact_pii(input, Some(&config));
        assert!(result.contains("test@test.com"));
        assert!(result.contains("<KEY>"));
    }

    #[test]
    fn reversible_redaction_round_trips_operational_data() {
        let input = "Connect to 192.168.1.100 as admin@example.com";
        let mut session = RedactionSession::new();

        let redacted = session.redact(input, None);

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
        let mut session = RedactionSession::new();
        let _ = session.redact("admin@example.com", None);
        let debug = format!("{session:?}");

        assert_eq!(debug, "RedactionSession { redaction_count: 1, .. }");
        assert!(!debug.contains("admin@example.com"));
    }
}
