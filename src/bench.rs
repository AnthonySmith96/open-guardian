//! Leak-detection benchmark ("la prueba").
//!
//! Runs the **real production pipeline** — the exact router `open-guardian
//! start` serves — against a labeled corpus of leak attempts over real
//! loopback HTTP. A mock upstream records precisely what crossed the wire,
//! so "leak" is measured on bytes observed, not on internal state.
//!
//! Case files live in `benchmarks/corpus/*.toml`. Every case declares an
//! expectation (`redact`, `block`, `allow`, `restore`); cases marked
//! `known_gap = true` are reported honestly but do not fail the gate.

use crate::banner;
use crate::config::DlpConfig;
use crate::server::{self, ServerConfig};
use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Marker the proxy embeds in forwarded bodies for request-scoped
/// reversible redaction.
const REVERSIBLE_PLACEHOLDER: &str = "[[GUARDIAN_REDACTED";

/// Maximum tolerated false-positive rate on the benign corpus (percent).
const MAX_FALSE_POSITIVE_PERCENT: f64 = 2.0;

// ─────────────────────────────────────────────────────────────────────────────
// Corpus model
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Clone)]
struct CaseFile {
    case: Vec<Case>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    /// plain | evasion | placement | policy | response | benign
    category: String,
    /// request (secret tries to leave) | response (secret comes back in)
    #[serde(default = "default_request")]
    direction: String,
    /// redact | block | allow | restore
    expect: String,
    /// Literal that must not cross the wire (omit for benign cases).
    #[serde(default)]
    secret: Option<String>,
    /// Token assembled at run time (parts joined) and substituted for
    /// `{{SECRET}}` in `body`. GitHub push protection rejects pushes that
    /// contain format-valid synthetic vendor tokens even in test corpora;
    /// splitting keeps the public corpus committable without weakening
    /// the gated checks.
    #[serde(default)]
    secret_parts: Option<Vec<String>>,
    body: String,
    #[serde(default = "default_path")]
    path: String,
    #[serde(default = "default_json")]
    content_type: String,
    #[serde(default)]
    response_body: Option<String>,
    #[serde(default = "default_json")]
    response_content_type: String,
    /// preset | echo (echo returns what the upstream received, wrapped in JSON)
    #[serde(default = "default_preset")]
    response_mode: String,
    /// Honest documentation of a known miss: reported, never gated.
    #[serde(default)]
    known_gap: bool,
    #[serde(default)]
    note: Option<String>,
}

fn default_request() -> String {
    "request".to_string()
}
fn default_path() -> String {
    "/v1/chat/completions".to_string()
}
fn default_json() -> String {
    "application/json".to_string()
}
fn default_preset() -> String {
    "preset".to_string()
}

fn load_corpus(dir: &Path) -> Result<Vec<Case>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read corpus directory {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();

    let mut cases = Vec::new();
    for file in &files {
        let content = std::fs::read_to_string(file)
            .with_context(|| format!("cannot read corpus file {}", file.display()))?;
        let parsed: CaseFile = toml::from_str(&content)
            .with_context(|| format!("invalid corpus file {}", file.display()))?;
        cases.extend(parsed.case);
    }

    let mut seen = HashMap::new();
    for case in &cases {
        if seen.insert(&case.id, ()).is_some() {
            anyhow::bail!("duplicate corpus case id: {}", case.id);
        }
    }
    if cases.is_empty() {
        anyhow::bail!("corpus at {} contains no cases", dir.display());
    }
    Ok(cases)
}

fn validate_case(case: &Case) -> Result<()> {
    let valid_category = [
        "plain",
        "evasion",
        "placement",
        "policy",
        "response",
        "benign",
    ];
    let valid_direction = ["request", "response"];
    let valid_expect = ["redact", "block", "allow", "restore"];
    let valid_mode = ["preset", "echo"];

    if !valid_category.contains(&case.category.as_str()) {
        anyhow::bail!("case {}: invalid category '{}'", case.id, case.category);
    }
    if !valid_direction.contains(&case.direction.as_str()) {
        anyhow::bail!("case {}: invalid direction '{}'", case.id, case.direction);
    }
    if !valid_expect.contains(&case.expect.as_str()) {
        anyhow::bail!("case {}: invalid expect '{}'", case.id, case.expect);
    }
    if !valid_mode.contains(&case.response_mode.as_str()) {
        anyhow::bail!(
            "case {}: invalid response_mode '{}'",
            case.id,
            case.response_mode
        );
    }
    if case.direction == "response" && case.response_body.is_none() {
        anyhow::bail!("case {}: response direction needs response_body", case.id);
    }
    if case.expect == "restore" && case.response_mode != "echo" {
        anyhow::bail!(
            "case {}: restore expectation requires response_mode = \"echo\"",
            case.id
        );
    }
    if case.expect == "allow" && case.category != "benign" {
        anyhow::bail!("case {}: 'allow' is reserved for benign cases", case.id);
    }
    if (case.direction == "response" || case.expect == "restore")
        && case.secret.is_none()
        && case.secret_parts.is_none()
    {
        anyhow::bail!("case {}: this expectation needs a secret literal", case.id);
    }
    if let Some(parts) = &case.secret_parts {
        if parts.is_empty() {
            anyhow::bail!("case {}: secret_parts cannot be empty", case.id);
        }
        if case.body.matches("{{SECRET}}").count() != 1 {
            anyhow::bail!(
                "case {}: secret_parts requires exactly one {{{{SECRET}}}} in body",
                case.id
            );
        }
    }
    Ok(())
}

/// Materializes the request body and leak literal for a case, applying
/// run-time token assembly where the corpus splits a vendor-shaped token
/// (GitHub push protection rejects pushes containing format-valid synthetic
/// tokens, even inside test corpora).
fn materialize(case: &Case) -> (String, String) {
    match &case.secret_parts {
        Some(parts) => {
            let secret = parts.concat();
            (case.body.replace("{{SECRET}}", &secret), secret)
        }
        None => (case.body.clone(), case.secret.clone().unwrap_or_default()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock upstream
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
enum MockResponse {
    /// Reply with `{"echo": <received body>}` — proves placeholder
    /// restoration round-trips through response inspection.
    Echo,
    Preset {
        content_type: String,
        body: String,
    },
}

#[derive(Default)]
struct UpstreamState {
    response: Option<MockResponse>,
    requests: Vec<Vec<u8>>,
}

#[derive(Clone, Default)]
struct UpstreamHarness {
    inner: Arc<Mutex<UpstreamState>>,
}

impl UpstreamHarness {
    fn set_response(&self, response: Option<MockResponse>) {
        self.inner.lock().expect("upstream state").response = response;
    }

    /// Returns the body of the last request the upstream received.
    fn take_last(&self) -> Option<String> {
        let mut state = self.inner.lock().expect("upstream state");
        state
            .requests
            .pop()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }
}

async fn upstream_capture(State(harness): State<UpstreamHarness>, body: Bytes) -> Response {
    let response = {
        let mut state = harness.inner.lock().expect("upstream state");
        state.requests.push(body.to_vec());
        state.response.clone()
    };

    match response.unwrap_or(MockResponse::Preset {
        content_type: "application/json".to_string(),
        body: "{\"ok\":true}".to_string(),
    }) {
        MockResponse::Echo => {
            let received = String::from_utf8_lossy(&body).into_owned();
            let payload = serde_json::json!({ "echo": received }).to_string();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                payload,
            )
                .into_response()
        }
        MockResponse::Preset { content_type, body } => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, content_type.as_str())],
            body,
        )
            .into_response(),
    }
}

async fn spawn_mock_upstream() -> Result<(SocketAddr, UpstreamHarness, tokio::task::JoinHandle<()>)>
{
    let harness = UpstreamHarness::default();
    let app = Router::new()
        .route("/*path", any(upstream_capture))
        .with_state(harness.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("cannot bind mock upstream")?;
    let addr = listener.local_addr().context("mock upstream address")?;
    let task = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            tracing::error!("mock upstream stopped: {error}");
        }
    });
    Ok((addr, harness, task))
}

async fn spawn_proxy(router: Router) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("cannot bind benchmark proxy")?;
    let addr = listener.local_addr().context("benchmark proxy address")?;
    let task = tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("benchmark proxy stopped: {error}");
        }
    });
    Ok((addr, task))
}

// ─────────────────────────────────────────────────────────────────────────────
// Runner
// ─────────────────────────────────────────────────────────────────────────────

pub struct BenchOptions {
    pub corpus_dir: PathBuf,
    /// Override the rules file (e.g. upstream gitleaks.toml).
    pub rules_file: Option<PathBuf>,
    pub gate: bool,
    pub docs_path: Option<PathBuf>,
    pub json_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseOutcome {
    pub id: String,
    pub category: String,
    pub direction: String,
    pub expect: String,
    pub known_gap: bool,
    pub status: u16,
    pub forwarded: bool,
    pub leaked: bool,
    pub redacted: bool,
    pub restored: bool,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryStat {
    pub name: String,
    pub total: usize,
    pub forwarded: usize,
    pub blocked: usize,
    pub redacted: usize,
    pub leaked: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchSummary {
    pub engine_version: String,
    pub rules_file: String,
    pub rules_bytes: usize,
    pub rule_count: usize,
    pub corpus_dir: String,
    pub total_cases: usize,
    pub categories: Vec<CategoryStat>,
    pub outcomes: Vec<CaseOutcome>,
    pub false_positives: usize,
    pub benign_total: usize,
}

impl BenchSummary {
    pub fn false_positive_percent(&self) -> f64 {
        if self.benign_total == 0 {
            return 0.0;
        }
        100.0 * self.false_positives as f64 / self.benign_total as f64
    }

    pub fn gate_failures(&self) -> Vec<&CaseOutcome> {
        self.outcomes
            .iter()
            .filter(|o| !o.known_gap && !o.passed)
            .collect()
    }

    pub fn known_gaps(&self) -> Vec<&CaseOutcome> {
        self.outcomes.iter().filter(|o| o.known_gap).collect()
    }

    pub fn gate_passed(&self) -> bool {
        self.gate_failures().is_empty()
            && self.false_positive_percent() <= MAX_FALSE_POSITIVE_PERCENT
    }
}

/// Raw observation of one exchange, before expectation evaluation.
#[derive(Debug, Clone)]
struct Observed {
    status: u16,
    forwarded: bool,
    leaked: bool,
    redacted: bool,
    restored: bool,
    upstream_mutated: bool,
    block_detail: Option<String>,
}

fn expectation_met(expect: &str, observed: &Observed) -> bool {
    match expect {
        // Benign traffic must pass semantically unchanged.
        "allow" => observed.forwarded && !observed.upstream_mutated && observed.status == 200,
        // Fail-closed: rejected by the proxy, never reached the upstream.
        "block" => observed.status == 403 && !observed.forwarded,
        // A secret that would otherwise cross the wire was replaced or the
        // exchange was rejected. `leaked == false` plus `forwarded` is the
        // contract: an undetected secret would have arrived verbatim.
        "redact" => observed.forwarded && !observed.leaked,
        // The differentiator: placeholder upstream, original value restored
        // locally in the response.
        "restore" => observed.forwarded && !observed.leaked && observed.restored,
        _ => false,
    }
}

/// JSON-semantic comparison: the proxy re-serializes bodies (key order,
/// whitespace), so byte equality would report false mutations.
fn semantically_different(original: &str, observed: &str) -> bool {
    match (
        serde_json::from_str::<serde_json::Value>(original),
        serde_json::from_str::<serde_json::Value>(observed),
    ) {
        (Ok(a), Ok(b)) => a != b,
        _ => original != observed,
    }
}

fn extract_block_detail(client_body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(client_body)
        .ok()
        .and_then(|value| {
            value
                .get("details")
                .and_then(|d| d.as_str())
                .map(str::to_string)
        })
}

fn proxy_config(mock_addr: SocketAddr, rules_file: &str) -> ServerConfig {
    ServerConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 0,
        default_upstream: format!("http://{mock_addr}"),
        routes: HashMap::new(),
        audit_log_path: None,
        // The corpus is a single client; the limiter would only add noise.
        requests_per_minute: Some(0),
        timeout_seconds: 30,
        verbose: false,
        dlp_config: DlpConfig {
            rules_files: vec![rules_file.to_string()],
            ..DlpConfig::default()
        },
        load_balancer: None,
        security: None,
        vault: None,
    }
}

pub async fn run(opts: &BenchOptions) -> Result<BenchSummary> {
    let cases = load_corpus(&opts.corpus_dir)?;
    for case in &cases {
        validate_case(case)?;
    }

    let rules_file = opts
        .rules_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(&DlpConfig::default().rules_files[0]));
    let rules_bytes = std::fs::metadata(&rules_file)
        .map(|m| m.len() as usize)
        .unwrap_or(0);

    let (mock_addr, harness, mock_task) = spawn_mock_upstream().await?;
    let (router, rule_count) =
        server::build_router(&proxy_config(mock_addr, &rules_file.to_string_lossy())).await?;
    let (proxy_addr, proxy_task) = spawn_proxy(router).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("cannot build benchmark client")?;

    let mut outcomes: Vec<CaseOutcome> = Vec::with_capacity(cases.len());

    for case in &cases {
        harness.set_response(match (case.response_mode.as_str(), &case.response_body) {
            ("echo", _) => Some(MockResponse::Echo),
            (_, Some(body)) => Some(MockResponse::Preset {
                content_type: case.response_content_type.clone(),
                body: body.clone(),
            }),
            _ => None,
        });

        let (request_body, secret) = materialize(case);

        let response = client
            .post(format!("http://{proxy_addr}{}", case.path))
            .header(reqwest::header::CONTENT_TYPE, &case.content_type)
            .body(request_body.clone())
            .send()
            .await
            .with_context(|| format!("case {}: request failed", case.id))?;

        let status = response.status().as_u16();
        let client_body = response.text().await.unwrap_or_default();
        let upstream_body = harness.take_last();
        let forwarded = upstream_body.is_some();
        let secret = secret.as_str();

        let leaked = if case.direction == "response" {
            !secret.is_empty() && client_body.contains(secret)
        } else {
            upstream_body
                .as_deref()
                .is_some_and(|body| !secret.is_empty() && body.contains(secret))
        };
        let redacted = if case.direction == "response" {
            case.response_body
                .as_deref()
                .is_some_and(|preset| client_body != preset)
        } else {
            upstream_body
                .as_deref()
                .is_some_and(|body| body.contains(REVERSIBLE_PLACEHOLDER))
        };
        let restored =
            case.response_mode == "echo" && !secret.is_empty() && client_body.contains(secret);
        let upstream_mutated = upstream_body
            .as_deref()
            .is_some_and(|observed| semantically_different(&request_body, observed));

        let observed = Observed {
            status,
            forwarded,
            leaked,
            redacted,
            restored,
            upstream_mutated,
            block_detail: (status == 403)
                .then(|| extract_block_detail(&client_body))
                .flatten(),
        };

        let passed = case.known_gap || expectation_met(&case.expect, &observed);
        outcomes.push(CaseOutcome {
            id: case.id.clone(),
            category: case.category.clone(),
            direction: case.direction.clone(),
            expect: case.expect.clone(),
            known_gap: case.known_gap,
            status,
            forwarded,
            leaked,
            redacted: observed.redacted,
            restored,
            passed,
            block_detail: observed.block_detail,
            note: case.note.clone(),
        });
    }

    mock_task.abort();
    proxy_task.abort();

    let summary = summarize(
        outcomes,
        &opts.corpus_dir,
        &rules_file,
        rules_bytes,
        rule_count,
    );

    if let Some(path) = &opts.json_path {
        std::fs::write(path, serde_json::to_string_pretty(&summary)?)
            .with_context(|| format!("cannot write JSON report to {}", path.display()))?;
    }
    if let Some(path) = &opts.docs_path {
        std::fs::write(path, render_docs(&summary))
            .with_context(|| format!("cannot write benchmark document to {}", path.display()))?;
    }

    print_summary(&summary);

    if opts.gate && !summary.gate_passed() {
        banner::print_error(&format!(
            "benchmark gate failed: {} case(s), {:.1}% false positives",
            summary.gate_failures().len(),
            summary.false_positive_percent()
        ));
        for failure in summary.gate_failures() {
            banner::print_error(&format!(
                "  case {} (expect {}): status={}, forwarded={}, leaked={}, redacted={}",
                failure.id,
                failure.expect,
                failure.status,
                failure.forwarded,
                failure.leaked,
                failure.redacted
            ));
        }
        anyhow::bail!("detection benchmark gate failed");
    }

    Ok(summary)
}

fn summarize(
    outcomes: Vec<CaseOutcome>,
    corpus_dir: &Path,
    rules_file: &Path,
    rules_bytes: usize,
    rule_count: usize,
) -> BenchSummary {
    let mut categories: Vec<CategoryStat> = Vec::new();
    for outcome in &outcomes {
        if let Some(stat) = categories.iter_mut().find(|s| s.name == outcome.category) {
            stat.total += 1;
            stat.forwarded += usize::from(outcome.forwarded);
            stat.blocked += usize::from(!outcome.forwarded && outcome.status == 403);
            stat.redacted += usize::from(outcome.redacted);
            stat.leaked += usize::from(outcome.leaked);
        } else {
            categories.push(CategoryStat {
                name: outcome.category.clone(),
                total: 1,
                forwarded: usize::from(outcome.forwarded),
                blocked: usize::from(!outcome.forwarded && outcome.status == 403),
                redacted: usize::from(outcome.redacted),
                leaked: usize::from(outcome.leaked),
            });
        }
    }
    categories.sort_by(|a, b| a.name.cmp(&b.name));

    let benign_total = outcomes.iter().filter(|o| o.category == "benign").count();
    let false_positives = outcomes
        .iter()
        .filter(|o| o.category == "benign" && !o.passed)
        .count();

    BenchSummary {
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        rules_file: rules_file.to_string_lossy().into_owned(),
        rules_bytes,
        rule_count,
        corpus_dir: corpus_dir.to_string_lossy().into_owned(),
        total_cases: outcomes.len(),
        categories,
        outcomes,
        false_positives,
        benign_total,
    }
}

fn print_summary(summary: &BenchSummary) {
    banner::print_step(&format!(
        "Benchmark: {} cases, {} rule(s) from {}",
        summary.total_cases, summary.rule_count, summary.rules_file
    ));
    for stat in &summary.categories {
        println!(
            "  {:<10} {:>3} cases | forwarded {:>3} | blocked {:>3} | redacted {:>3} | LEAKS {}",
            stat.name, stat.total, stat.forwarded, stat.blocked, stat.redacted, stat.leaked
        );
    }
    println!(
        "  false positives: {}/{} benign ({:.1}%)",
        summary.false_positives,
        summary.benign_total,
        summary.false_positive_percent()
    );
    let gaps = summary.known_gaps();
    if !gaps.is_empty() {
        banner::print_warning(&format!(
            "known gaps (documented, not gated): {}",
            gaps.len()
        ));
        for gap in gaps {
            println!("  - {} [{}]", gap.id, gap.note.as_deref().unwrap_or(""));
        }
    }
    let failures = summary.gate_failures();
    if failures.is_empty() {
        banner::print_success("gate: PASS (0 leaks, 0 misses on gated cases)");
    } else {
        banner::print_error(&format!("gate: {} gating failure(s)", failures.len()));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic benchmark document
// ─────────────────────────────────────────────────────────────────────────────

fn render_docs(summary: &BenchSummary) -> String {
    let mut doc = String::new();

    doc.push_str("# Detection benchmark\n\n");
    doc.push_str(
        "> Generated by `open-guardian bench` from `benchmarks/corpus/`. Do not edit\n\
         > by hand: CI regenerates this document and rejects drift, and any leak or\n\
         > missed detection on the gated corpus fails the build.\n\n",
    );
    doc.push_str(&format!(
        "- Engine: open-guardian v{}\n- Rules file: `{}` ({} bytes, {} rules)\n- Corpus: {} cases\n\n",
        summary.engine_version,
        summary.rules_file,
        summary.rules_bytes,
        summary.rule_count,
        summary.total_cases
    ));

    doc.push_str("## Results\n\n");
    doc.push_str("| Category | Cases | Forwarded | Blocked | Redacted | Leaks |\n");
    doc.push_str("| --- | ---: | ---: | ---: | ---: | ---: |\n");
    for stat in &summary.categories {
        doc.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            stat.name, stat.total, stat.forwarded, stat.blocked, stat.redacted, stat.leaked
        ));
    }
    doc.push_str(&format!(
        "\nFalse positives on the benign corpus: {}/{} ({:.1}%), tolerated maximum {:.0}%.\n\n",
        summary.false_positives,
        summary.benign_total,
        summary.false_positive_percent(),
        MAX_FALSE_POSITIVE_PERCENT
    ));

    doc.push_str("## Known gaps (documented, not gated)\n\n");
    let gaps = summary.known_gaps();
    if gaps.is_empty() {
        doc.push_str("None.\n\n");
    } else {
        doc.push_str("| Case | What happens | Note |\n| --- | --- | --- |\n");
        for gap in gaps {
            let what = if gap.leaked {
                "secret crossed the wire".to_string()
            } else if gap.forwarded {
                "forwarded without redaction".to_string()
            } else {
                format!("status {}", gap.status)
            };
            doc.push_str(&format!(
                "| `{}` | {} | {} |\n",
                gap.id,
                what,
                gap.note.as_deref().unwrap_or("")
            ));
        }
        doc.push('\n');
    }

    doc.push_str(
        "## Methodology\n\n\
         - Every case drives the full production pipeline over real loopback HTTP —\
         \n  smuggling checks, rate limiting, field extraction, the DLP engine, the\
         \n  obfuscation probe, forwarding, and response-side inspection — using the\
         \n  same router `open-guardian start` serves.\n\
         - The mock upstream records the exact bytes that crossed the wire; a\
         \n  **leak** means the literal secret appeared in what the upstream received\
         \n  (request cases) or what the client received (response cases).\n\
         - Evasion cases (encoding, entities, homoglyphs, zero-width characters)\
         \n  must be rejected fail-closed, not forwarded.\n\
         - `restore` cases prove the differentiator: the upstream only ever sees\
         \n  placeholders, while the local client gets the original value back.\n\
         - Benign cases must arrive semantically unchanged (JSON-semantic compare,\n\
         \n  since the proxy legitimately re-serializes bodies).\n",
    );

    doc
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_parses_with_unique_ids_and_valid_expectations() {
        let cases = load_corpus(Path::new("benchmarks/corpus")).expect("corpus loads");
        assert!(cases.len() >= 50, "corpus looks too small: {}", cases.len());
        for case in &cases {
            validate_case(case).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[test]
    fn corpus_file_rejects_unknown_fields() {
        let raw = r#"
            [[case]]
            id = "x"
            category = "plain"
            expect = "redact"
            body = "{}"
            bogus_field = true
        "#;
        assert!(toml::from_str::<CaseFile>(raw).is_err());
    }

    #[test]
    fn semantic_comparison_ignores_reserialization() {
        assert!(!semantically_different(
            r#"{"b":1,"a":"x"}"#,
            r#"{"a":"x","b":1}"#
        ));
        assert!(semantically_different(
            r#"{"a":"secret"}"#,
            r#"{"a":"[[GUARDIAN_REDACTED:x:0:RULE]]"}"#
        ));
    }

    #[test]
    fn expectations_are_strict() {
        let base = Observed {
            status: 200,
            forwarded: true,
            leaked: false,
            redacted: true,
            restored: false,
            upstream_mutated: false,
            block_detail: None,
        };

        assert!(expectation_met("allow", &base));
        assert!(expectation_met("redact", &base));
        assert!(!expectation_met("block", &base));
        assert!(!expectation_met("restore", &base));

        let blocked = Observed {
            status: 403,
            forwarded: false,
            ..base.clone()
        };
        assert!(expectation_met("block", &blocked));
        assert!(!expectation_met("redact", &blocked));

        let leaked = Observed {
            leaked: true,
            ..base.clone()
        };
        assert!(!expectation_met("redact", &leaked));

        let restored = Observed {
            restored: true,
            ..base
        };
        assert!(expectation_met("restore", &restored));
    }

    /// The regression gate, baked into the ordinary test run: the full corpus
    /// must pass against the shipped rules on every platform we build for.
    #[tokio::test]
    async fn full_corpus_passes_the_gate() {
        let summary = run(&BenchOptions {
            corpus_dir: PathBuf::from("benchmarks/corpus"),
            rules_file: None,
            gate: false,
            docs_path: None,
            json_path: None,
        })
        .await
        .expect("benchmark runs");

        assert!(
            summary.gate_passed(),
            "detection regression: {:#?}",
            summary.gate_failures()
        );
    }

    /// The benchmark document must be byte-stable so CI can reject drift.
    #[tokio::test]
    async fn generated_document_is_deterministic() {
        let options = |path: PathBuf| BenchOptions {
            corpus_dir: PathBuf::from("benchmarks/corpus"),
            rules_file: None,
            gate: false,
            docs_path: Some(path),
            json_path: None,
        };

        run(&options(PathBuf::from("target/bench-doc-a.md")))
            .await
            .expect("benchmark runs");
        run(&options(PathBuf::from("target/bench-doc-b.md")))
            .await
            .expect("benchmark runs");

        let first = std::fs::read_to_string("target/bench-doc-a.md").expect("doc a written");
        let second = std::fs::read_to_string("target/bench-doc-b.md").expect("doc b written");
        assert_eq!(
            first, second,
            "rendered document must not vary between runs"
        );
    }
}
