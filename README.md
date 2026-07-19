# Open-Guardian

Local-first privacy control plane and secret boundary for OpenAI-compatible applications.

Open-Guardian sits between a chat, RAG system, agent framework, or personal second brain and its model provider. It keeps local routing local by default, applies deterministic policy, replaces sensitive request values with reversible request-scoped placeholders, and resolves provider credentials outside model context.

It is intentionally **not** a second-brain UI, indexer, autonomous agent, or general secret-reveal API. A project such as Smith can own notes, scopes, retrieval, chat, and consolidation while reusing Open-Guardian for provider egress and secrets.

## Project status

The `main` release is v0.1.5. The v0.2 work described here is under active development and should be treated as pre-release until reviewed and tagged.

Implemented on this branch:

- Loopback-only bind and local Ollama-compatible upstream by default.
- External providers require an explicit model route, explicit load-balancer activation, or the explicit `--upstream` CLI override.
- Request scanning for all message roles, content parts, `prompt`, `input`, `instructions`, and tool-call arguments.
- Reversible, per-request DLP placeholders restored only after the response returns locally.
- Complete response inspection, including SSE, with a 16 MiB bound.
- Typed `SecretRef`, reusable `SecretBroker`, zeroizing `SecretValue`, `env://`, and namespaced native `keychain://` backends.
- Feature-gated read-only age v1 portable vault with strict bounded payload validation.
- Provider credentials injected only into the upstream `Authorization` header.
- Read-compatible migration from deprecated `key_env` configuration.
- Deterministic audit/block policy; optional AI Judge disabled by default.
- Optional HMAC rule integrity that fails closed once configured.
- Reproducible binary dependency graph through committed `Cargo.lock`.

Not implemented yet:

- A user-facing reveal/copy UI and local authorization flow.
- Writable portable-vault operations, pairing, recovery, rollback anchors, or device revocation.
- RAG, note ingestion, Obsidian-style index, chat UI, or session compression.
- Token-by-token response streaming. SSE is buffered by design until a safe streaming protocol is implemented.
- A sensitivity classifier and per-scope consent UI for external-provider routing.

See [ADR-0001](docs/adr/0001-portable-vault-format.md) for the portable vault security design and implementation gates.

## Why this belongs next to a second brain

A useful operational memory contains IPs, ports, hostnames, runbooks, provider configuration, and references to credentials. A normal hosted chat can make that knowledge convenient, but sending the entire operational context to a third party defeats the privacy goal.

Open-Guardian separates responsibilities:

```text
Second brain / app
  owns scopes, retrieval, citations, chat, and explicit user intent
        |
        | OpenAI-compatible request + model alias
        v
Open-Guardian
  owns local routing, egress policy, DLP, SecretRef, and audit metadata
        |
        +--> local Ollama/vLLM by default
        |
        `--> explicit external route with brokered provider credential
```

The model can receive an opaque reference such as:

```text
{{secret:vault://infrastructure/proxmox#password}}
```

It does not receive the referenced value. A future native UI can render that reference as a Reveal/Copy capsule and ask `SecretBroker` only after local authorization.

## Security invariants

1. A literal provider API key is not valid route configuration.
2. Provider credentials are resolved after routing, outside the JSON body, and injected only as an HTTP header.
3. Missing, empty, malformed, duplicated, or unsupported credential configuration fails closed.
4. `SecretValue` is not cloneable or serializable, redacts `Debug`, and zeroizes its owned buffer on drop.
5. Request DLP mappings live only for one request and never enter configuration, logs, or the upstream body.
6. A token minted by another request cannot resolve in the current request.
7. All model responses pass DLP before request placeholders are restored locally.
8. Invalid configuration is an error; Open-Guardian does not silently fall back after finding a broken config file.
9. The network listener and unmatched model route are local by default.
10. The proxy does not execute model-generated shell commands or expose filesystem tools.

These controls do not protect an already compromised, unlocked device. Malware with process-memory, clipboard, accessibility, or screen access remains inside the trust boundary.

## Architecture

```text
HTTP client
   |
   | 1. path/header checks + global rate limit
   | 2. strict JSON parsing (non-JSON denied by default)
   | 3. extract supported text fields
   | 4. DLP block or request-scoped reversible redaction
   | 5. Unicode normalization + deterministic risk checks
   | 6. audit/block decision
   | 7. deterministic model route
   | 8. SecretBroker resolves only the selected provider credential
   v
Upstream model
   |
   | 9. bounded full-body/SSE buffering
   | 10. response DLP
   | 11. local restoration of this request's placeholders
   v
HTTP client
```

Main code areas:

```text
src/
├── lib.rs                 reusable library entry point
├── secrets/
│   ├── mod.rs             SecretBroker, backend trait, env backend, SecretValue
│   ├── keychain.rs        read-only, namespaced native credential-store backend
│   ├── vault.rs           bounded read-only age decryption backend
│   ├── vault_payload.rs   strict versioned plaintext parser
│   └── reference.rs       canonical SecretRef parser and serde contract
├── pipeline/extract.rs    supported OpenAI-compatible request text extraction
├── security/
│   ├── dlp.rs             detection, irreversible response redaction, reversible sessions
│   ├── normalizer.rs      Unicode/code-aware normalization
│   ├── injection_scanner.rs
│   ├── threat_engine.rs
│   ├── integrity.rs       optional HMAC rule manifest
│   └── judge.rs           legacy optional local judge
├── proxy.rs               upstream HTTP and final response reconstruction
├── router.rs              deterministic complexity router
├── server.rs              Axum request orchestration
├── config.rs              strict TOML discovery, parsing, and migration
└── main.rs                CLI and service entry point

rules/                     modular deterministic signatures
guardian.toml              documented local-first example configuration
docs/adr/                  security and architecture decisions
```

Some older security modules remain present but are not wired into the active request path. Documentation and tests must distinguish implemented boundaries from planned infrastructure.

## Quick start

### Requirements

- Rust 1.88 or newer.
- Optional: Ollama or another OpenAI-compatible server on `127.0.0.1:11434`.
- Optional external route: provider key supplied through the configured SecretBroker backend.

### Build and verify

```bash
git clone https://github.com/AnthonySmith96/open-guardian.git
cd open-guardian

cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --release --locked
```

### Run locally

```bash
# guardian.toml defaults to 127.0.0.1:8080 and local Ollama-compatible upstream.
cargo run --locked -- start

# Equivalent forced-local shortcut with another port.
cargo run --locked -- start --local --port 18080

curl http://127.0.0.1:8080/health
```

Point an OpenAI-compatible client at:

```text
http://127.0.0.1:8080/v1
```

### Portable binary layout

For a standalone distribution, keep runtime resources beside the executable:

```text
open-guardian[.exe]
guardian.toml
rules/
  common.json
  jailbreaks_en.json
  jailbreaks_es.json
```

Configuration discovery order is:

1. `GUARDIAN_CONFIG` when explicitly set; the target must exist and parse.
2. `guardian.toml` beside the executable.
3. `guardian.toml` in the current working directory, for development.
4. Built-in local-first defaults when no file exists.

Relative dictionary paths are anchored to the configuration file that declares them.

Tagged GitHub releases package this complete layout for Linux x86_64, Windows x86_64, macOS Intel, and macOS Apple Silicon. Each release includes `SHA256SUMS` and GitHub build-provenance attestations. The workflow rejects tags that do not match the version in `Cargo.toml`.

## Configuration

The checked-in [guardian.toml](guardian.toml) is the complete annotated example. A minimal local profile is:

```toml
[server]
bind_address = "127.0.0.1"
port = 8080
default_upstream = "http://127.0.0.1:11434/v1"
requests_per_minute = 600

[security]
block_threshold = 50

[security.dlp]
email_redaction = true
credit_card_redaction = true
secret_redaction = true
ssn_redaction = true
ip_redaction = true
phone_redaction = true

[security.policies]
default_action = "audit"
dlp_action = "redact"

[[security.policies.dictionaries]]
id = "common"
path = "rules/common.json"
enabled = true

[judge]
ai_judge_enabled = false

[load_balancer]
enabled = false
```

### Explicit external routes

External egress is opt-in through a route:

```toml
[routes."work-gpt"]
url = "https://api.openai.com/v1"
model = "gpt-4.1-mini"
credential = "{{secret:env://OPENAI_API_KEY}}"

[routes."local-qwen"]
url = "http://127.0.0.1:11434/v1"
model = "qwen3:8b"
```

Set the credential in the parent process or service environment:

```bash
export OPENAI_API_KEY="..."
cargo run --locked -- start
```

Do not put a literal key in `guardian.toml`. The deprecated field:

```toml
key_env = "OPENAI_API_KEY"
```

is migrated in memory to `{{secret:env://OPENAI_API_KEY}}` with a warning. Defining both forms is an error.

### Semantic load balancer

The deterministic load balancer scores the already-inspected request text and selects a fast or smart tier. It is disabled in the default profile because the example tiers are external.

```toml
[load_balancer]
enabled = true
smart_threshold = 40

[load_balancer.fast]
url = "https://api.groq.com/openai"
model = "llama-3.1-8b-instant"
credential = "{{secret:env://GROQ_API_KEY}}"

[load_balancer.smart]
url = "https://api.openai.com/v1"
model = "gpt-4.1"
credential = "{{secret:env://OPENAI_API_KEY}}"
```

Enabling this block is an explicit choice to send matching prompts to those providers.

## SecretBroker

### Canonical reference

```text
{{secret:<backend>://<logical/path>#<optional-field>}}
```

Examples:

```text
{{secret:env://OPENAI_API_KEY}}
{{secret:keychain://providers/openai#api_key}}
{{secret:vault://infrastructure/proxmox#password}}
```

`env://` and `keychain://` are enabled in standard binaries. `keychain://` maps only to the fixed application service `io.github.anthonysmith96.open-guardian`, so a reference cannot select another application's credential namespace. The read-only `vault://` backend is registered only when a `[vault]` section explicitly supplies its encrypted file and identity reference. Build with `--no-default-features` for a headless binary that only registers `env://`. Other schemes parse as references but fail closed until their backend is registered.

The parser rejects:

- Missing wrappers or schemes.
- Uppercase/non-canonical backend names.
- Absolute, empty, repeated, or traversal path segments.
- Backslashes, control characters, raw whitespace, query strings, nested schemes, and multiple fragments.
- References longer than 2 KiB.

### Native keychain

Provision an exact reference through a hidden terminal prompt:

```bash
open-guardian secret set '{{secret:keychain://providers/openai#api_key}}'
```

Then use the opaque reference in configuration:

```toml
credential = "{{secret:keychain://providers/openai#api_key}}"
```

Delete it explicitly when it is no longer needed:

```bash
open-guardian secret delete '{{secret:keychain://providers/openai#api_key}}'
```

The secret value is never accepted as a command-line argument, so it does not enter shell history or the process list. These commands cannot enumerate entries and reject every scheme except `keychain://`. A platform may show its own authorization prompt. Headless builds made with `--no-default-features` omit both the native backend and these commands; use `env://` there.

### Rust library API

The broker is available without starting the proxy:

```rust,ignore
use open_guardian::secrets::{EnvironmentBackend, SecretBroker, SecretRef};

let mut broker = SecretBroker::new();
broker.register(EnvironmentBackend)?;

let reference: SecretRef = "{{secret:env://OPENAI_API_KEY}}".parse()?;
let value = broker.resolve(&reference).await?;

// Only a narrow transport/tool boundary should call expose_secret().
send_authorization_header(value.expose_secret()).await?;
```

Models and generic application DTOs must not receive a `SecretBroker` handle or `SecretValue`.

### Portable vault

The prototype can read an age v1 encrypted `.guardian.age` file after its X25519 identity is resolved outside the vault:

```toml
[vault]
path = "secrets/personal.guardian.age"
identity = "{{secret:keychain://vaults/personal#age_identity}}"

[routes."work-gpt"]
url = "https://api.openai.com/v1"
credential = "{{secret:vault://providers/openai#api_key}}"
```

The encrypted payload and decrypted plaintext are bounded; format versions, timestamps, logical paths, fields, duplicates, and unknown properties are validated. Parsed values are zeroizing and cannot be serialized or printed through `Debug`.

This is explicitly read-only and pre-production. It currently has no rollback anchor, interoperability fixture with the independent Go implementation, initialization, pairing, recovery, mutation, or revocation. Production writes remain gated by the ADR's atomic-write, fuzz, rollback, interoperability, and heap-leak requirements. See [ADR-0001](docs/adr/0001-portable-vault-format.md).

## DLP behavior

### Request redaction

In `redact` mode, each match becomes a token similar to:

```text
[[GUARDIAN_REDACTED:<random-request-nonce>:<index>:IP]]
```

The model retains the category and surrounding context without receiving the original value. The mapping is held in zeroizing memory for this request only.

If an upstream response echoes that exact token, the original value is restored after response DLP and only on the local side. Fabricated, stale, or cross-request tokens remain inert.

### Response handling

All responses, including `text/event-stream`, are buffered to a maximum of 16 MiB before release. This prevents a provider from bypassing a regex by splitting a secret across TCP chunks or SSE events.

The current proxy is deliberately text-only: a non-UTF-8 upstream body is uninspectable and therefore fails closed with `502` instead of bypassing DLP. Valid response bytes are preserved exactly; Open-Guardian does not append delimiters or normalize provider output.

The tradeoff is deliberate: v0.2 does not provide token-by-token delivery. A future streaming design must prove boundary-safe incremental inspection before this changes.

Provider-generated sensitive data that was not represented by a current request placeholder remains irreversibly redacted.

### Categories

Current detectors cover email, credit-card-like numbers, US SSNs, phone-like numbers, IPv4 addresses, common provider tokens, AWS access keys, GitHub tokens, Slack tokens, bearer tokens, and generic key/token assignments. Regex DLP can produce false positives and is not a complete secret classifier.

## Policy profiles

Threat/injection policy and DLP action are separate:

| Setting | Effect |
|---|---|
| `default_action = "audit"` | Default second-brain profile. Forward risky text and add `X-Guardian-Risk` when a blocking threshold is reached. |
| `default_action = "block"` | Strict firewall profile. Return 403 for threshold/blocking signatures. |
| `default_action = "allow"` | Log but do not enforce threat decisions. Not recommended. |
| `default_action = "redact"` | Deprecated compatibility alias for `audit`. |
| `dlp_action = "redact"` | Use reversible request placeholders and sanitize response-only leaks. |
| `dlp_action = "block"` | Reject a request/response when a configured DLP violation is found. |

Audit is the default because a runbook may legitimately contain `curl`, `rm`, SQL, templates, or incident-response examples. Open-Guardian classifies text; it does not execute it.

The legacy AI Judge can be enabled for compatibility, but it is not a security boundary and adds another inference call. It is disabled and fail-closed by default.

## Rule integrity

Fresh installs start without a machine-specific signing key. To enable local tamper detection:

```bash
export GUARDIAN_HMAC_KEY="a-long-random-machine-secret"
cargo run --locked -- sign rules
cargo run --locked -- start
```

Once either side of the integrity contract is present, Open-Guardian fails closed:

- Key present but manifest missing/invalid: startup fails.
- Manifest present but key missing: startup fails.
- Signed rule changed or deleted: startup fails.

`rules/.manifest.json` is machine-specific and gitignored. Keep the same HMAC key available to the service; do not commit it.

## CLI

```text
open-guardian start [--bind IP] [--port PORT] [--upstream URL] [--local] [--verbose]
open-guardian audit [PATH]
open-guardian sign [RULES_DIR]
open-guardian service install|uninstall|start|stop
open-guardian secret set|delete '{{secret:keychain://logical/path#field}}'
```

- `start` runs the proxy.
- `audit` performs a shallow local check for selected sensitive config files and obvious public binds; it is not a full security scanner.
- `sign` writes the local HMAC rule manifest.
- `service` integrates with the native service manager.
- `secret` provisions or removes an exact entry in Open-Guardian's native keychain namespace.

`--bind 0.0.0.0` is an explicit exposure decision. The current server has no LAN authentication layer; do not publish it directly to the internet.

## Logging and audit data

Application logs rotate daily under `logs/` beside the executable. Security events can be written as JSONL through `security.audit_log_path`.

Current audit events contain timestamp, event type, path, category, score/severity, and risk tags. They must not contain prompts, secret values, authorization headers, or DLP mappings. New log fields require security review.

## Development

Run the complete gate before committing:

```bash
cargo fmt -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo check --all-targets --no-default-features --locked
cargo build --release --locked
git diff --check
```

Security-sensitive changes should remain small and independently reviewable. At minimum, add tests for:

- Parser rejection and boundary values.
- Fail-closed configuration paths.
- No secret in `Debug`, errors, logs, JSON, or request bodies.
- Chunk/event boundary behavior.
- Cross-request token isolation.
- External-route opt-in and credential-header injection.
- Platform-specific resource discovery.

Do not add a secret backend that shells out, reads arbitrary paths, or prompts interactively from `resolve()`. Administrative operations belong in separate explicit APIs.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contributor workflow. It is being updated alongside v0.2; code and this README are authoritative when older guidance conflicts.

## Roadmap

### v0.2 hardening

- Complete request-field pipeline integration.
- Local network and model routing defaults.
- Response/SSE DLP closure.
- Reversible request-scoped DLP.
- Typed SecretBroker and provider credential migration.
- Documentation, migration notes, and integration tests.

### Native secrets

- Cross-platform keychain resolution in a fixed application namespace.
- Administrative set/delete CLI separate from request-time resolve; enumeration is intentionally unsupported.
- Local authorization and reveal/copy UX contract.
- Clipboard expiry where platform support is reliable.

### Portable vault

- Current: read-only age 0.12.1 backend and bounded versioned payload parser.
- Remaining: independent `age`/`rage` golden interoperability fixtures.
- Atomic writes and native rollback anchor.
- Device pairing, recovery, revocation, and conflict handling.
- Fuzz, corruption, heap-leak, and cross-platform tests.

### Second-brain integration

- A minimal adapter contract for scope/sensitivity metadata.
- Explicit external-provider consent before routing private context.
- SecretRef capsules that a UI can reveal without involving a model.
- No direct shell/filesystem execution path from chat.

## Threat model and non-goals

Open-Guardian aims to reduce accidental egress, configuration mistakes, common prompt attacks, and credential handling inside model clients.

It does not claim to:

- Make an external provider private after data is intentionally sent.
- Detect every secret or prompt injection.
- Secure a compromised operating system or unlocked process.
- Replace a password manager, endpoint protection, sandbox, or network firewall.
- Decide whether a generated command is operationally safe to execute.
- Erase historical ciphertext or secrets already revealed to a revoked device.

The safest deployment is a local model, loopback listener, explicit routes, no autonomous execution, and a device you control.

## License

Apache-2.0. See [LICENSE](LICENSE).
