//! # Semantic Load Balancer — Complexity-Based Routing
//!
//! Routes prompts to a cheap/fast tier (Groq, Llama-3-8b) or a premium/smart tier
//! (GPT-4, Opus) based on a deterministic heuristic score.
//!
//! The score is computed in microseconds — no LLM calls, no network, no latency overhead.

use crate::config::LoadBalancerConfig;
use open_guardian::secrets::SecretRef;

// ─────────────────────────────────────────────────────────────────────────────
//  Routing Tier
// ─────────────────────────────────────────────────────────────────────────────

/// The chosen tier for a routing decision.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RoutingTier {
    /// Low-cost, high-speed economy tier (e.g. Groq / Llama-3-8b).
    Fast,
    /// High-intelligence premium tier (e.g. GPT-4-Turbo / Claude Opus).
    Smart,
}

impl std::fmt::Display for RoutingTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingTier::Fast => write!(f, "TIER_FAST"),
            RoutingTier::Smart => write!(f, "TIER_SMART"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Routing Decision
// ─────────────────────────────────────────────────────────────────────────────

/// Fully-resolved routing decision returned by [`route`].
#[derive(Debug)]
pub struct RoutingDecision {
    /// Computed complexity score (0-100+).
    pub score: u32,
    /// Selected routing tier.
    pub tier: RoutingTier,
    /// Upstream base URL for the selected tier.
    pub upstream_url: String,
    /// Opaque credential resolved only at the upstream transport boundary.
    pub credential: Option<SecretRef>,
    /// Model to rewrite in the JSON body (if any).
    pub model: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Complexity Keywords
// ─────────────────────────────────────────────────────────────────────────────

/// Keywords that each add +20 to the complexity score.
const COMPLEXITY_KEYWORDS: &[&str] = &[
    "code",
    "function",
    "rust",
    "python",
    "debug",
    "architect",
    "analysis",
    "refactor",
    "complex",
    "mathematics",
];

// ─────────────────────────────────────────────────────────────────────────────
//  Scoring Algorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Calculate a complexity score for the given text using deterministic heuristics.
///
/// # Algorithm
/// | Source                              | Points         |
/// |-------------------------------------|----------------|
/// | Base score                          | +10            |
/// | Length factor                       | +1 per 50 chars|
/// | Complexity keyword (case-insensitive)| +20 each      |
/// | Code block (```) or JSON `{}`       | +30            |
///
/// The maximum score is unbounded but typical prompts cap around 150.
pub fn calculate_complexity(text: &str) -> u32 {
    let mut score: u32 = 10;
    let lower = text.to_lowercase();

    // Length factor: +1 per 50 characters
    score = score.saturating_add((text.len() as u32) / 50);

    // Keyword factor: +20 per detected keyword
    for kw in COMPLEXITY_KEYWORDS {
        if lower.contains(kw) {
            score = score.saturating_add(20);
        }
    }

    // Syntax indicators: +30 for code blocks or JSON objects
    if text.contains("```") || (text.contains('{') && text.contains('}')) {
        score = score.saturating_add(30);
    }

    score
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public Router
// ─────────────────────────────────────────────────────────────────────────────

/// Score `text` and return a fully-resolved [`RoutingDecision`].
///
/// # Safety — Body Stream Integrity
/// **IMPORTANT:** `text` MUST be sourced from text already extracted and
/// parsed from the JSON body (e.g. during the DLP scan loop). Never pass
/// a reference to the raw Axum body stream — that would drain the stream
/// and reproduce the Content-Length: 0 bug.
pub fn route(text: &str, config: &LoadBalancerConfig) -> RoutingDecision {
    let score = calculate_complexity(text);
    let threshold = config.smart_threshold.unwrap_or(40);

    if score >= threshold {
        // ── TIER_SMART: High-complexity → Premium model ──
        let tier_cfg = &config.smart_tier;
        RoutingDecision {
            score,
            tier: RoutingTier::Smart,
            upstream_url: tier_cfg.url.clone(),
            credential: tier_cfg.credential.clone(),
            model: tier_cfg.model.clone(),
        }
    } else {
        // ── TIER_FAST: Low-complexity → Economy model ──
        let tier_cfg = &config.fast_tier;
        RoutingDecision {
            score,
            tier: RoutingTier::Fast,
            upstream_url: tier_cfg.url.clone(),
            credential: tier_cfg.credential.clone(),
            model: tier_cfg.model.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_score() {
        // Minimal text — only base score (10) applies.
        let score = calculate_complexity("Hi");
        assert_eq!(score, 10, "Minimal text should be base score 10");
    }

    #[test]
    fn test_simple_prompt_scores_below_threshold() {
        let score = calculate_complexity("Hello, how are you?");
        assert!(
            score < 40,
            "Simple greeting should score below 40, got {score}"
        );
    }

    #[test]
    fn test_complex_prompt_scores_above_threshold() {
        let score = calculate_complexity(
            "Write a complex rust function to architect and refactor the module analysis",
        );
        assert!(
            score >= 40,
            "Complex technical prompt should score >= 40, got {score}"
        );
    }

    #[test]
    fn test_code_block_adds_syntax_bonus() {
        let without = calculate_complexity("explain sorting");
        let with_block =
            calculate_complexity("explain sorting\n```python\ndef bubble_sort(lst): pass\n```");
        assert!(
            with_block > without,
            "Code block should increase score: {with_block} vs {without}"
        );
    }

    #[test]
    fn test_json_structure_adds_syntax_bonus() {
        let without = calculate_complexity("parse this");
        let with_json = calculate_complexity("parse this {\"key\": \"value\"}");
        assert!(with_json > without);
    }

    #[test]
    fn test_multiple_keywords_stack() {
        // "rust" (+20) + "debug" (+20) + "refactor" (+20) = 60+base
        let score = calculate_complexity("rust debug refactor");
        assert!(
            score >= 70,
            "Three keywords should yield >= 70, got {score}"
        );
    }
}
