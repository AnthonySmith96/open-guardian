# Changelog

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
