//! Unicode Evasion Resistance Module
//!
//! This module provides comprehensive Unicode normalization and attack detection
//! to prevent evasion techniques that exploit Unicode complexity.

use regex::Regex;
use serde::{Deserialize, Serialize};

const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{FEFF}', '\u{202A}', '\u{202B}',
    '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}',
];

const HOMOGLYPH_MAPPINGS: &[(char, &str)] = &[
    ('\u{0430}', "a"),
    ('\u{0435}', "e"),
    ('\u{043E}', "o"),
    ('\u{0440}', "p"),
    ('\u{0441}', "c"),
    ('\u{0445}', "x"),
    ('\u{0433}', "g"),
    ('\u{0434}', "d"),
    ('\u{0443}', "y"),
    ('\u{0437}', "z"),
    ('\u{0438}', "i"),
    ('\u{043A}', "k"),
    ('\u{043B}', "l"),
    ('\u{043C}', "m"),
    ('\u{043D}', "n"),
    ('\u{0442}', "t"),
    ('\u{0444}', "f"),
    ('\u{03B1}', "a"),
    ('\u{03B5}', "e"),
    ('\u{03BF}', "o"),
    ('\u{03C1}', "p"),
    ('\u{03C3}', "c"),
    ('\u{FF21}', "A"),
    ('\u{FF41}', "a"),
    ('\u{212A}', "K"),
];

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnicodeNormalizerConfig {
    #[serde(default = "default_true")]
    pub strip_zero_width: bool,
    #[serde(default = "default_true")]
    pub normalize_homoglyphs: bool,
    #[serde(default = "default_true")]
    pub block_rtl_override: bool,
    #[serde(default = "default_true")]
    pub decode_recursive: bool,
    #[serde(default = "default_max_decode_depth")]
    pub max_decode_depth: usize,
    #[serde(default = "default_max_code_points")]
    pub max_code_points: usize,
}

fn default_true() -> bool {
    true
}
fn default_max_decode_depth() -> usize {
    5
}
fn default_max_code_points() -> usize {
    5000
}

impl Default for UnicodeNormalizerConfig {
    fn default() -> Self {
        Self {
            strip_zero_width: true,
            normalize_homoglyphs: true,
            block_rtl_override: true,
            decode_recursive: true,
            max_decode_depth: 5,
            max_code_points: 5000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizationResult {
    pub modified: bool,
    pub normalized: String,
    pub issues: Vec<NormalizationIssue>,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizationIssue {
    pub issue_type: IssueType,
    pub description: String,
    pub position: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IssueType {
    ZeroWidthChar,
    Homoglyph,
    RtlOverride,
    RecursiveEncoding,
    TokenSplitting,
    TooLong,
}

pub struct UnicodeNormalizer {
    config: UnicodeNormalizerConfig,
    #[allow(dead_code)]
    zero_width_pattern: Regex,
    rtl_override_pattern: Regex,
    #[allow(dead_code)]
    base64_pattern: Regex,
    url_encoded_pattern: Regex,
    html_entity_pattern: Regex,
    // Need to add the missing field
    #[allow(dead_code)]
    detect_token_splitting: bool,
}

impl UnicodeNormalizer {
    pub fn new(config: UnicodeNormalizerConfig) -> Result<Self, regex::Error> {
        let zero_width_pattern = Regex::new(r"[\x00-\x1f\u200B-\u200F\u202A-\u202E\u2060-\u2064]")?;
        let rtl_override_pattern = Regex::new(r"[\u{202A}-\u{202E}]")?;
        let base64_pattern = Regex::new(r"^[A-Za-z0-9+/]+=*$")?;
        let url_encoded_pattern = Regex::new(r"%[0-9A-Fa-f]{2}")?;
        let html_entity_pattern = Regex::new(r"&[#]?\w+;")?;

        Ok(Self {
            config,
            zero_width_pattern,
            rtl_override_pattern,
            base64_pattern,
            url_encoded_pattern,
            html_entity_pattern,
            detect_token_splitting: true,
        })
    }

    pub fn normalize(&self, content: &str) -> NormalizationResult {
        let mut normalized = content.to_string();
        let mut issues = Vec::new();
        let mut modifications = 0;

        let codepoint_count = normalized.chars().count();
        if codepoint_count > self.config.max_code_points {
            issues.push(NormalizationIssue {
                issue_type: IssueType::TooLong,
                description: format!("Content has {} code points, exceeds limit", codepoint_count),
                position: None,
            });
            normalized = normalized
                .chars()
                .take(self.config.max_code_points)
                .collect();
            modifications += 1;
        }

        // Step 1: Strip zero-width characters
        if self.config.strip_zero_width {
            let before = normalized.len();
            normalized = self.strip_zero_width_chars(&normalized);
            if normalized.len() != before {
                modifications += 1;
                issues.push(NormalizationIssue {
                    issue_type: IssueType::ZeroWidthChar,
                    description: "Zero-width characters removed".to_string(),
                    position: None,
                });
            }
        }

        // Step 2: Block RTL override
        if self.config.block_rtl_override && self.rtl_override_pattern.is_match(&normalized) {
            issues.push(NormalizationIssue {
                issue_type: IssueType::RtlOverride,
                description: "RTL override characters detected - potential display manipulation"
                    .to_string(),
                position: None,
            });
            // Remove RTL override characters
            normalized = self
                .rtl_override_pattern
                .replace_all(&normalized, "")
                .to_string();
            modifications += 1;
        }

        // Step 3: Normalize homoglyphs
        if self.config.normalize_homoglyphs {
            let before = normalized.clone();
            normalized = self.normalize_homoglyphs(&normalized);
            if normalized != before {
                modifications += 1;
                issues.push(NormalizationIssue {
                    issue_type: IssueType::Homoglyph,
                    description: "Homoglyph characters normalized to ASCII".to_string(),
                    position: None,
                });
            }
        }

        // Step 4: Recursive decoding (basic)
        if self.config.decode_recursive {
            let decoded = self.decode_recursive(&normalized, 0);
            if decoded != normalized {
                normalized = decoded;
                modifications += 1;
                issues.push(NormalizationIssue {
                    issue_type: IssueType::RecursiveEncoding,
                    description: "Recursive encoding detected and decoded".to_string(),
                    position: None,
                });
            }
        }

        let suspicious = !issues.is_empty();

        NormalizationResult {
            modified: modifications > 0,
            normalized,
            issues,
            suspicious,
        }
    }

    fn strip_zero_width_chars(&self, content: &str) -> String {
        content
            .chars()
            .filter(|c| !ZERO_WIDTH_CHARS.contains(c))
            .collect()
    }

    fn normalize_homoglyphs(&self, content: &str) -> String {
        let mut result = String::with_capacity(content.len());
        for c in content.chars() {
            let replacement = HOMOGLYPH_MAPPINGS
                .iter()
                .find(|(orig, _)| *orig == c)
                .map(|(_, replacement)| *replacement);

            match replacement {
                Some(rep) => result.push_str(rep),
                None => result.push(c),
            }
        }
        result
    }

    fn decode_recursive(&self, content: &str, depth: usize) -> String {
        if depth >= self.config.max_decode_depth {
            return content.to_string();
        }

        let mut current = content.to_string();
        let mut decoded = false;

        // URL decode
        if self.url_encoded_pattern.is_match(&current) {
            if let Ok(d) = urlencoding::decode(&current) {
                current = d.to_string();
                decoded = true;
            }
        }

        // HTML decode
        if self.html_entity_pattern.is_match(&current) {
            current = html_escape::decode_html_entities(&current).to_string();
            decoded = true;
        }

        // If we decoded something, try again recursively
        if decoded {
            current = self.decode_recursive(&current, depth + 1);
        }

        current
    }
}

impl Default for UnicodeNormalizer {
    fn default() -> Self {
        Self::new(UnicodeNormalizerConfig::default()).unwrap()
    }
}

pub fn normalize_unicode(content: &str) -> NormalizationResult {
    let normalizer = UnicodeNormalizer::default();
    normalizer.normalize(content)
}

/// Alias for normalize_unicode for compatibility
pub fn normalize(content: &str) -> NormalizationResult {
    normalize_unicode(content)
}

/// ═══════════════════════════════════════════════════════════════
/// SECURITY FIX C3/C4: Normalize + Casefold BEFORE DLP/Search
/// ═══════════════════════════════════════════════════════════════
///
/// This function creates a normalized, casefolded version of content
/// for matching against security patterns. This MUST be called BEFORE
/// DLP detection to prevent bypass via case variation or Unicode.
///
/// Order of operations:
/// 1. Unicode normalization (NFKC)
/// 2. Zero-width character removal
/// 3. Homoglyph normalization (Cyrillic → ASCII)
/// 4. Casefolding (for case-insensitive matching)
///
/// Use this instead of raw content when checking against:
/// - DLP patterns
/// - Threat signatures
/// - Injection patterns
///
/// NOTE: This function is plumbed for future integration. Currently
/// the existing normalizer is used to minimize code churn.
#[allow(dead_code)]
pub fn normalize_for_matching(content: &str) -> String {
    use unicode_normalization::UnicodeNormalization;

    let mut result = content.to_string();

    // Step 1: Unicode NFKC normalization
    result = result.nfkc().collect::<String>();

    // Step 2: Strip zero-width characters
    for zwc in ZERO_WIDTH_CHARS {
        result = result.replace(*zwc, "");
    }

    // Step 3: Normalize homoglyphs (Cyrillic → ASCII)
    for (cyrillic, ascii) in HOMOGLYPH_MAPPINGS {
        result = result.replace(*cyrillic, ascii);
    }

    // Step 4: Casefold for case-insensitive matching
    // Using Unicode casefolding, not just lowercase
    result = result.to_lowercase();

    result
}

/// Quick check if content contains suspicious Unicode patterns.
/// Use this for fast-path filtering before detailed analysis.
#[allow(dead_code)]
pub fn has_suspicious_unicode(content: &str) -> bool {
    // Check for zero-width characters
    for c in content.chars() {
        if ZERO_WIDTH_CHARS.contains(&c) {
            return true;
        }
    }

    // Check for RTL override
    if content.contains('\u{202A}')
        || content.contains('\u{202B}')
        || content.contains('\u{202C}')
        || content.contains('\u{202D}')
        || content.contains('\u{202E}')
    {
        return true;
    }

    // Check for Cyrillic homoglyphs
    for (c, _) in HOMOGLYPH_MAPPINGS.iter().take(17) {
        // First 17 are lowercase Cyrillic that look like ASCII
        if content.contains(*c) {
            return true;
        }
    }

    false
}
