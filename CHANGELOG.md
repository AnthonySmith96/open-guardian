# Changelog

## v0.6.0 - Context DLP: clean tool output before it enters the model (2026-08-22)

### New

- **`open-guardian mcp-gateway -- <command>`**: wraps any MCP stdio server
  and pipes the harness through it. Harness → downstream traffic forwards
  verbatim; on the way back, every tool result (the JSON-RPC `CallToolResult`
  shape — identified structurally, no request tracking needed) is sanitized
  before it reaches the model. `initialize`, `tools/list`, notifications,
  resources, prompts, and sampling pass through untouched, so the gateway is
  invisible to both ends. Exits with the downstream's exit code.
- **`open-guardian sanitize`**: stdin → stdout through the DLP engine, for
  harness hooks and shell pipelines (`cat .env | open-guardian sanitize`);
  `--file` reads from disk. Status messages go to stderr — stdout stays
  pipe-clean. `--rules` (both commands) overrides the rules file for one
  invocation.
- **Shared sanitization pipeline**: Context DLP reuses the broker's output
  rule verbatim — irreversible in-place redaction of secrets/PII
  (`sk_live_…` → `<STRIPE-KEY>`), then an obfuscation probe that suppresses
  the whole output when anything suspicious survives normalization
  (fail-closed, corpus-proven). For tool results, redaction walks the entire
  `result` tree (`content[].text`, `structuredContent` at any depth) and
  probes JSON numbers too (bare-digit Luhn cards).

### Fixed

- Stdio-protocol subcommands (`mcp`, `mcp-gateway`, `sanitize`) no longer
  print the startup banner or the config-loaded notice to stdout — stdout
  carries MCP JSON-RPC frames / sanitized payload only. Strict harnesses
  that reject non-protocol lines now work.

## v0.5.0 - Action Broker: privileged actions with out-of-band approval (2026-08-22)

### New

- **Action Broker daemon** (`open-guardian broker start`): executes
  allowlisted privileged actions on behalf of AI agents behind four gates —
  ed25519-**signed policies** (exact argv, no shell; tampered or unsigned
  policies refuse to start), **out-of-band approval** (6-char code visible
  only on the operator channel; wrong codes are audited and rejected),
  **hash-chained audit**, and **output DLP** (command stdout/stderr runs
  through the same DLP engine as the proxy; obfuscated secrets suppress the
  whole output). Loopback-only IPC with separate agent/admin bearer tokens.
- **MCP server** (`open-guardian mcp`): stdio transport via the official Rust
  SDK (`rmcp`), three tools (`guardian_list_actions`,
  `guardian_request_action`, `guardian_request_status`), harness-agnostic
  (Claude Code, Cursor, Goose, …). The agent channel can never see approval
  codes or approve anything.
- **Operator CLI**: `approve` (code prompt or `--code`/`--yes`), `deny`,
  `requests` (shows pending codes), `broker request` (terminal testing), and
  `policy keygen|sign|verify|sudoers` (surgical
  `/etc/sudoers.d/guardian-broker` lines with `visudo -f` instructions).
- **Hash-chained audit log**: every security event (proxy and broker) is now
  written as JSONL with `seq`/`prev`/`hash` linking; `open-guardian verify`
  walks the chain and reports edits, deletions, or reordering with line
  numbers. One chain per process (proxy and broker keep separate files).
- **Secrets in executed actions**: policy env entries are `{{secret:...}}`
  references resolved only at execution time and injected straight into the
  child's environment (env/keychain/vault backends); unresolvable references
  abort the action before anything runs. Results are delivered exactly once
  and expire (Vault response-wrapping semantics; Teleport-style pending →
  approve/deny → TTL state machine).
- Docs: [docs/BROKER.md](docs/BROKER.md) (architecture, honest threat model,
  sudoers guide), `examples/broker-policy.toml`.

### Changed

- Audit log lines gain `seq`, `prev`, and `hash` fields (previously plain
  JSONL). Existing logs remain readable; `open-guardian verify` validates the
  new format.

## v0.4.0 - The proof: regression-gated leak benchmark (2026-08-22)

### New

- **`open-guardian bench`**: replays a labeled leak corpus through the real
  production pipeline (the same router `start` serves) against an in-process
  recording mock upstream, and measures leaks on the bytes that actually
  crossed the wire. `--gate` exits non-zero on any leak or missed detection;
  `--docs` renders a deterministic benchmark document; `--rules` accepts any
  gitleaks-format file.
- **`benchmarks/corpus/`**: 73 public, labeled cases — 27 secret families in
  plain text plus Luhn-valid cards/emails/IPs/phones, obfuscated variants
  (percent/double-percent encoding, HTML entities, zero-width characters,
  Cyrillic homoglyphs, case folding), secrets hidden in every request field
  (`prompt`, `input`, `instructions`, tool-call arguments, `metadata.note`,
  deep nesting, `name`), model-echoed secrets in JSON/SSE responses, an
  SSE-echo restoration round-trip, and an 11-case benign look-alike corpus.
- **`docs/BENCHMARK.md`**: generated by `open-guardian bench`, verified
  byte-identical by CI on every change; states results and known gaps
  (fragmented secrets, SSE-split secrets) explicitly.
- CI now runs the benchmark as a **regression gate** (any leak on the gated
  corpus fails the build) plus a `gitleaks-compat` job that loads the pinned
  upstream gitleaks.toml and runs the corpus against it (report-only: 43/73
  leak upstream, including every obfuscated variant — documented, not gated).

### Fixed

- Homoglyph folding now runs **after** casefolding, so uppercase Cyrillic/Greek
  look-alikes (О, А, …) can no longer evade detection (corpus-proven).
- Phone detection now requires separator-delimited groups: bare digit runs
  (UUIDs, order numbers, semvers, checksums) no longer false-positive.
- Secrets hidden in `name` fields are redacted; `name` was wrongly treated as
  protocol structure and skipped by the extractor.
- Official gitleaks.toml is now a true drop-in: rules without `regex`
  (path-scoped) are skipped with a notice, and the regex size limit was raised
  so upstream's giant `generic-api-key` alternation compiles.

## v0.3.0 - The egress pivot: DLP engine, rule files, per-IP limits (2026-08-22)

### Direction change

Open-Guardian is now a **local egress data-protection proxy for AI agents**.
The prompt-injection defense stack (keyword scanner, threat signature engine,
optional Ollama AI Judge) was removed: keyword/substring detection was
trivially bypassed, could not run case-insensitively on the wired path, and a
network proxy cannot distinguish untrusted retrieved content from user
instructions. Prompt-injection defense belongs in the agent runtime. The
project's defensible core — reversible redaction, the SecretBroker, and the
egress boundary — is now the entire product.

### Removed

- `injection_scanner`, `threat_engine`, `judge` modules and the jailbreak
  rule dictionaries (`rules/common.json`, `rules/jailbreaks_en.json`,
  `rules/jailbreaks_es.json`).
- `[judge]`, `[security.policies]` (dictionaries, `allowed_patterns`,
  `default_action`), and `security.block_threshold` configuration; stale
  v0.2 config now fails fast with a parse error instead of lingering.
- Dead `env_security`/`path_security` prototypes and the broken
  `tools/gen_manifest` scripts (the `open-guardian sign` subcommand is the
  supported manifest path).
- Unused dependencies: `moka`, `seahash`, `tower`, `tower-http`, `hyper`,
  `unidecode`, `libc`.

### New

- `DlpEngine`: external secret rules in **gitleaks-compatible TOML**
  (`rules/secrets.toml`, 27 curated rules) with `keywords` prefilters,
  Shannon `entropy` gates, and `secretGroup`-scoped redaction. The upstream
  gitleaks.toml works as a drop-in replacement. Invalid rules abort startup.
- Credit card detection now requires a **Luhn checksum**, eliminating the
  most common false positive class.
- **Obfuscated-secret rejection**: requests are re-scanned after NFKC +
  casefold + homoglyph folding + recursive URL/HTML decoding; secrets that
  only surface decoded (e.g. percent-encoded keys) are rejected fail-closed
  because they cannot be safely rewritten in place.
  (`security.dlp.block_on_obfuscated`, default true.)
- **Arbitrary-field scanning**: unclassified JSON string leaves
  (`metadata.note`, vendor extensions, ...) are now scanned and redacted —
  previously only known fields were covered.
- **Per-client-IP token-bucket rate limiting** replaces the single global
  counter; keyed on socket peer address only (forwarded headers cannot spoof
  limiter identity), with idle-bucket pruning. `server.requests_per_minute`
  is now per-IP (default 1200; 0 disables).
- Hop-by-hop header stripping (`sanitize_headers`) is now wired into the
  upstream forward path.
- Rule integrity manifests now cover `.toml` rule files as well as `.json`.

### Changed

- `dlp_action` moved to `security.dlp.action`; response-side one-way
  placeholders now use rule IDs (`<GROQ-API-KEY>`) instead of `<KEY>`.
- Startup banner reports the loaded secret-rule count instead of judge state.

### Compatibility notes

- v0.2 configuration files with `[judge]` or `[security.policies]` sections
  must be updated; unknown fields are rejected by design.
- `X-Guardian-Risk` audit headers no longer exist (they tagged injection
  findings, which were removed).

## v0.2.0 - Local-first hardening and SecretBroker (2026-07-18)

### Security fixes

- Wired the general request extractor into the active pipeline for all message roles, content parts, prompts, inputs, instructions, and tool arguments.
- Bind to `127.0.0.1` by default; public/LAN binds require explicit configuration.
- Route unmatched models to local Ollama-compatible inference by default.
- Keep the distributed `guardian.toml` load balancer disabled and all deterministic rule dictionaries enabled.
- Disable the external semantic load balancer and legacy AI Judge by default.
- Fail closed when a configured provider credential is missing, empty, malformed, duplicated, or unsupported.
- Reject unknown configuration fields, including literal `api_key` fields, instead of silently ignoring them.
- Reject model endpoints that embed userinfo, query parameters, fragments, or non-HTTP schemes; normalize `/v1` joins without duplicate slashes.
- Buffer all responses, including SSE, to a 16 MiB inspection limit before release.
- Reject non-UTF-8 upstream bodies that cannot pass text DLP, and stop appending a newline to provider responses.
- Make `block` and `redact` cover the same secret, bearer-token, phone, and IPv4 detector categories.
- Return normal CLI errors instead of panicking on invalid service metadata or missing/empty rule-signing keys.
- Block traversal and encoded traversal in every proxied path, including paths under `/v1` and `/api`.
- Keep upstream URLs, paths, and internal transport/backend errors out of client-facing error bodies.
- Fail closed if an inspected JSON request cannot be reserialized instead of falling back to its original unredacted bytes.
- Inspect JSON and SSE response string fields structurally so DLP cannot corrupt numeric metadata, and restore request-scoped placeholders without producing invalid JSON.
- Resolve configuration/rule resources predictably and fail on malformed discovered configuration.
- Make HMAC rule integrity opt-in for fresh installs but fail closed once a key or manifest establishes the contract.
- Commit `Cargo.lock` for reproducible binary dependency resolution.
- Remove the unmaintained direct `atty` dependency and unused `governor` stack; CI now denies RustSec findings with one documented build-time exception inherited from the latest `age` release.
- Pin CI actions, test on Rust 1.88 across Linux/macOS/Windows, and verify both desktop and headless feature sets.
- Package binaries with configuration, rules, documentation, SHA-256 checksums, and build-provenance attestations.

### New

- Added canonical `SecretRef` parsing and serde support.
- Added reusable `SecretBroker`, `SecretBackend`, zeroizing `SecretValue`, and `env://` backend as a Rust library API.
- Added a read-only `keychain://` backend confined to Open-Guardian's native credential-store namespace; `env://`-only headless builds remain available.
- Added explicit native-keychain set/delete commands with hidden input and no enumeration capability.
- Replaced provider `key_env` usage with typed `credential = "{{secret:...}}"` references; legacy configuration migrates in memory with a warning.
- Added per-request reversible DLP placeholders with random nonces and local post-response restoration.
- Added an age-v1-based portable vault ADR with explicit production implementation gates.
- Added a feature-gated, bounded v1 vault payload parser that rejects duplicate paths/fields and keeps parsed values zeroizing and non-serializable.
- Added a feature-gated, read-only age v1 `vault://` backend with bounded ciphertext/plaintext and X25519 device identities.
- Added explicit `[vault]` configuration so standard binaries can unlock a read-only portable vault through an `env://` or `keychain://` identity reference.
- Added a security reporting policy and documented the exact boundary between the read-only vault prototype and gated production writes.
- Changed the default policy to `audit` for runbook/second-brain workflows; strict `block` remains available.

### Compatibility notes

- Token-by-token SSE delivery is temporarily unavailable because response DLP is now fail-closed and boundary-safe.
- `default_action = "redact"` is a deprecated alias for `audit`; `dlp_action` controls actual DLP behavior.
- The writable `vault://` backend is not enabled yet.

## v0.1.5 - Security Hardening (2026-02-20)

### CRITICAL Security Fixes

**C1: Non-JSON Default Deny (CVE-class issue)**
- Added `allow_non_json_passthrough: false` config option (default)
- Non-JSON requests now BLOCKED by default (configurable explicit opt-in)
- Even in passthrough mode, raw body DLP scanning is applied
- Prevents complete security bypass via non-JSON requests

**C2: Expanded Scan Coverage**
- Created `src/pipeline/extract.rs` with comprehensive JSON string extraction
- Scans ALL message roles: user, system, assistant, tool, function
- Scans `/prompt` (completions), `/input` (embeddings), `/tool_calls/*/function/arguments`
- Prevents hiding malicious content in assistant/tool messages

**C3/C4: Casefold + Normalize Before DLP**
- Added `normalize_for_matching()` function in `normalizer.rs`
- Applies: Unicode NFKC → zero-width removal → homoglyph norm → casefold
- DLP and threat detection now use normalized form
- Prevents case-based and Unicode evasion attacks

**C5: Streaming Response Handling**
- SSE (`text/event-stream`) now passes through unmodified without buffering
- Removed unconditional newline append that corrupted binary responses
- Streaming preserved for real-time LLM responses

**C6: Panic Path Removal**
- Replaced `headers_ref().unwrap()` with safe `if let Some(headers)` patterns
- All unwraps in proxy response handling removed
- Proper error propagation with `?` operator

**C7: Judge Prompt Injection Protection**
- Restructured judge prompt with XML-style delimiters
- User content escaped with `html_escape::encode_text()`
- Clear separation between instructions and analyzed text

**C8: Fix Allowlist Bypass**
- Changed substring `contains()` to bounded word matching
- Pattern must be surrounded by whitespace/punctuation or string bounds
- "git pull" no longer matches "git pull && rm -rf /"

### Changed Files
- `src/config.rs` — Added security config section
- `src/server.rs` — Non-JSON handling, security config
- `src/pipeline/` — New module for scan extraction (extract.rs, mod.rs)
- `src/pipeline/extract.rs` — Complete JSON string extractor
- `src/proxy.rs` — Streaming handling, panic removal
- `src/security/normalizer.rs` — `normalize_for_matching()` function
- `src/security/threat_engine.rs` — Bounded pattern matching
- `src/security/judge.rs` — Structured prompt separation
- `src/main.rs` — Added `mod pipeline;`

### Architecture
Started migration to pipeline architecture:
- Phase 0: Extract → Normalize → Scan → Decide → Apply
- New `pipeline/` directory for future security stages

---

## v0.1.4 - Previous Release

*See commit history for v0.1.4 changes*
