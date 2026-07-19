# Contributing to Open-Guardian

Open-Guardian handles model egress and secret material. Changes should be small, testable, and reviewable without trusting a large refactor.

## Principles

1. **Local first.** A fresh/default configuration binds to loopback and routes to a local model.
2. **Deterministic boundary.** Routing, credentials, DLP, authorization, and policy do not depend on an LLM decision.
3. **No autonomous execution.** The proxy classifies text; it does not execute generated commands.
4. **Secret values stay out of models and generic DTOs.** Models may see `SecretRef`, never `SecretValue`.
5. **Fail closed at boundaries.** Invalid config, credentials, redaction application, integrity, and bounded response inspection stop the operation.
6. **Runbooks remain discussable.** `audit` is the default control-plane policy; strict `block` remains explicit.
7. **No invented cryptography.** Portable vault work follows accepted ADRs and interoperability tests.

## Setup

Requirements:

- Rust 1.88 or newer.
- No model server is required for unit tests.
- Ollama is optional for manual local-proxy testing.

```bash
git clone https://github.com/AnthonySmith96/open-guardian.git
cd open-guardian

cargo test --all-targets --locked
cargo clippy --all-targets -- -D warnings
```

## Required gate

Run this before every commit/PR:

```bash
cargo fmt -- --check
cargo test --all-targets --locked
cargo clippy --all-targets -- -D warnings
cargo build --release --locked
git diff --check
```

Never weaken a gate with `|| true` in CI or packaging.

## Commit strategy

- One security claim or behavior per commit.
- Keep mechanical formatting separate from semantic changes.
- Include the regression test in the same commit as the fix.
- Do not mix vault crypto, UI, routing, and DLP changes.
- Explain compatibility and migration behavior in the commit/PR description.
- Preserve unrelated work in a dirty tree.

Recommended prefixes:

```text
fix:      closes an incorrect or unsafe behavior
feat:     introduces a bounded capability
refactor: changes structure without changing the security contract
docs:     documentation/ADR only
test:     tests/fixtures only
build:    toolchain, dependency lock, CI, packaging
```

## Security review checklist

For any change involving secrets, DLP, providers, logs, configuration, or network behavior, answer:

- Can a literal value enter a prompt, model body, URL, error, `Debug`, log, trace, panic, JSON, or audit record?
- What happens when a backend, key, config field, file, or response chunk is missing or malformed?
- Is the default still loopback/local/audit?
- Can a model choose a backend, path, recipient, provider, or shell command?
- Are sizes, counts, recursion, and response bodies bounded before allocation?
- Does streaming have exactly the same security policy as buffered responses?
- Are sensitive temporary buffers zeroized where ownership allows it?
- Does the test prove data placement, not merely a return value?
- Is a migration ambiguous or silently permissive?

## SecretBroker contributions

`SecretBackend::resolve` is deliberately narrow and read-only.

A backend must not:

- Launch a shell or arbitrary executable.
- Read an arbitrary filesystem path derived from a model.
- Prompt interactively inside request handling.
- Perform pairing, migration, set, delete, or recovery as a side effect.
- Include a secret value in any error.
- Cache plaintext without a documented TTL, ownership model, and zeroization path.

A backend must:

- Own one canonical lowercase scheme.
- Validate backend-specific path and field rules.
- Fail closed on empty/unavailable values.
- Return `SecretValue`.
- Include unit tests and, when applicable, platform integration tests.
- Document headless/mobile behavior and its trust assumptions.

Administrative APIs (`set`, `delete`, `pair`, `revoke`, `recover`) are separate from `resolve` and require their own authorization design.

Portable vault implementation must comply with [ADR-0001](docs/adr/0001-portable-vault-format.md). Do not enable production writes before every gate in that ADR is met.

## DLP contributions

When adding/changing a detector:

1. Add positive and negative fixtures.
2. Test boundary splitting and overlap with more specific patterns.
3. Test category toggles.
4. Test reversible request redaction and local restoration.
5. Confirm provider-generated response values do not get accidentally restored.
6. Measure false positives on operational text such as IPs, ports, hashes, commands, and code.

Never log a matched substring in a test failure or production event.

## Request extraction

New OpenAI-compatible text-bearing fields must be added to `src/pipeline/extract.rs` with:

- Exact JSON pointer tests.
- All relevant roles/content variants.
- A replacement test proving redaction updates the intended field.
- A fail-closed behavior when the pointer can no longer be updated.

Do not recursively scan arbitrary JSON strings without defining whether fields such as model IDs, URLs, binary payloads, and metadata are in scope.

## Provider and routing changes

- Default routing must remain local.
- External egress requires an explicit route, load-balancer opt-in, or CLI override.
- Each external route uses `credential = "{{secret:...}}"`; literal keys are invalid.
- A route change must swap URL, model, and credential together.
- Incoming client `Authorization` is not forwarded upstream.
- Provider credentials are injected only at the transport boundary.

Integration tests should use a loopback mock server and assert where the credential appears.

## Rule dictionaries

Rule files live under `rules/` and are deterministic inputs. Include:

- Unique ID.
- Normalized pattern.
- Category and severity.
- Regex flag.
- Test or reproducible fixture.

Remember that a second-brain runbook may legitimately contain destructive commands as text. The default `audit` policy must keep such material discussable.

If rule integrity is enabled during testing, regenerate the local manifest with the same test HMAC key. Never commit `rules/.manifest.json` or the key.

## Documentation

Update documentation in the same commit when behavior or defaults change.

- README describes current behavior only.
- Security/crypto design decisions go in `docs/adr/`.
- CHANGELOG records user-visible changes.
- Planned features must be labeled as planned; do not present scaffolding as an active boundary.

## Reporting security issues

Do not publish live credentials, private prompts, vault files, or exploitable deployment details in a public issue. Provide a minimal synthetic reproduction and contact maintainers privately when disclosure could put users at risk.

## License

Contributions are licensed under Apache-2.0, matching the repository.
