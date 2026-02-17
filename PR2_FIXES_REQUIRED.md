# Guardian PR #2 — Required Fixes for v0.1.2 Merge

**Source:** PR Review by AnthonySmith96  
**Status:** 5 Critical Issues Identified  
**Target:** v0.1.2 Release

---

## ISSUE 1: Memory Leak (CRITICAL)

**Location:** `src/rate_limit.rs`  
**Problem:** HashMap initialized without background cleaner task  
**Impact:** Will eventually OOM the server  
**Fix Required:**
- Implement background task to clean expired rate limit entries
- Add TTL/expiration logic to HashMap entries
- Consider using `tokio::time::interval` for periodic cleanup

**Reference:** Look for HashMap initialization in rate_limit.rs

---

## ISSUE 2: Streaming Performance (CRITICAL)

**Location:** `src/server.rs`  
**Problem:** Buffering the whole body breaks SSE (Server-Sent Events)  
**Impact:** AI responses that stream (text/event-stream) fail  
**Fix Required:**
- Implement pass-through for `text/event-stream` content type
- Don't buffer entire body for streaming responses
- Maintain buffering for non-streaming content (smuggling protection)

**Reference:** Look for body buffering logic in server.rs

---

## ISSUE 3: Hardcoded Secrets (CRITICAL)

**Location:** 
- `tools/` directory
- `src/integrity.rs`

**Problem:** Hardcoded keys and paths to specific developer machines  
**Impact:** Security risk, not portable, breaks on other systems  
**Fix Required:**
- Remove all hardcoded secrets
- Use environment variables or config files
- Add `.env.example` template
- Ensure no paths to `/home/hera/` or specific user directories

**Check for:**
- API keys in source
- File paths with usernames
- Hardcoded certificates

---

## ISSUE 4: Dev Experience (HIGH)

**Location:** `src/integrity.rs`  
**Problem:** Integrity check needs bypass flag for local development  
**Impact:** Manual edits to rules crash the server during development  
**Fix Required:**
- Add `--dev` or `--skip-integrity` CLI flag
- Only enforce integrity checks in production/release mode
- Document the flag in README

---

## ISSUE 5: Cleanup & Versioning (MEDIUM)

**Tasks:**
1. **Delete duplicate:** `tools/gen_manifest.rs` (duplicate exists elsewhere)
2. **Update version:** `Cargo.toml` → v0.1.2
3. **Update version:** `README.md` → v0.1.2  
4. **Refine README narrative:** Present as official release, not just a fork

---

## TESTING REQUIREMENTS

For each fix, add test cases:

1. **Memory Leak:** Test that HashMap size stays bounded over time
2. **Streaming:** Test SSE endpoint streams without buffering
3. **Secrets:** Test that no hardcoded values exist (grep check)
4. **Dev Flag:** Test that `--dev` flag bypasses integrity checks
5. **General:** All existing tests must still pass (`cargo test`)

---

## ACCEPTANCE CRITERIA

- [ ] All 5 issues resolved
- [ ] Test cases written and passing
- [ ] `cargo test` passes
- [ ] `cargo fmt` clean
- [ ] `cargo clippy` clean
- [ ] Version bumped to v0.1.2 in Cargo.toml and README
- [ ] PR updated with fix summary

---

## REFERENCE LINKS

- Original PR: https://github.com/AnthonySmith96/open-guardian/pull/2
- Review comment: https://github.com/AnthonySmith96/open-guardian/pull/2#pullrequestreview-3810432862
- Rust skill: `/root/.openclaw/workspace/skills/rust/`

---

*Prepared for Opus 4.6 specialist agent — 2026-02-16*
