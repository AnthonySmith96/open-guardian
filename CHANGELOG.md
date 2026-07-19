# Changelog

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
- Resolve configuration/rule resources predictably and fail on malformed discovered configuration.
- Make HMAC rule integrity opt-in for fresh installs but fail closed once a key or manifest establishes the contract.
- Commit `Cargo.lock` for reproducible binary dependency resolution.
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
