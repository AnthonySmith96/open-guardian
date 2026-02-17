<p align="center">
  <h1 align="center">🛡️ Open-GuardIAn</h1>
  <p align="center"><strong>The High-Performance Firewall for AI Agents.</strong></p>
  <p align="center"><em>Built in Rust. Agent-First. Defense-in-Depth.</em></p>
  <p align="center">
    <a href="#-quickstart"><img src="https://img.shields.io/badge/Get_Started-blue?style=for-the-badge" alt="Get Started"></a>
    <a href="#-architecture"><img src="https://img.shields.io/badge/Architecture-purple?style=for-the-badge" alt="Architecture"></a>
    <a href="#%EF%B8%8F-configuration"><img src="https://img.shields.io/badge/Configuration-green?style=for-the-badge" alt="Configuration"></a>
    <a href="#-contributing"><img src="https://img.shields.io/badge/Contributing-orange?style=for-the-badge" alt="Contributing"></a>
  </p>
</p>

---

## 💡 What Is This?

Open-GuardIAn is a **high-performance security middleware / reverse proxy** built in Rust that sits between your applications and any LLM provider (OpenAI, Groq, Ollama, Anthropic, etc.). It enforces real-time governance policies to prevent data leaks, block prompt injections, and stop agents from executing dangerous actions — all before the request ever reaches the model.

```
 Your App ──▶ Open-GuardIAn ──▶ LLM Provider
                   │
            ┌──────┴───────┐
            │  Layer 1     │  ← DLP Anonymizer + Threat Engine (Rust, <20µs)
            │  Layer 2     │  ← Heuristic Injection Scanner (Rust, <20µs)
            │  Layer 3     │  ← AI Judge: qwen2.5:0.5b via Ollama (Contextual)
            └──────────────┘
```

### 🏆 Why Open-GuardIAn vs. Python Gateways?

| Feature | **Open-GuardIAn** | Trylon / GPT Guard |
|---------|-------------------|-------------------|
| **Language** | 🦀 Rust | 🐍 Python |
| **Latency** | **<20µs** microsecond scan | 5-50ms |
| **DLP** | Anonymizer tokens (`<EMAIL>`, `<KEY>`) — preserves context for Agents | `[REDACTED]` or regex-only |
| **AI Intelligence** | Local LLM Judge with RAG context (qwen2.5:0.5b) | ❌ Regex only |
| **Agent-First** | ✅ `rm -rf` allowed for agents, blocked for attackers | ❌ Blocks all dangerous commands |
| **Fail-Safe** | Layer 1 & 2 provide Trylon-level security without GPU | Depends on service availability |
| **Multilingual** | 🌍 EN + ES dictionaries, add any language | English-only |

---

## 🎯 Who Is This For?

| Audience | Problem We Solve |
|----------|-----------------|
| **Agent builders** (AutoGPT, CrewAI, LangChain) | Prevent agents from executing `rm -rf /`, `curl | bash`, or destroying infrastructure — while still letting them use those tools legitimately |
| **RAG chatbot developers** | Stop end-users from jailbreaking your bot, leaking system prompts, or exfiltrating PII |
| **Enterprise teams** | Enforce DLP policies — no API keys, SSNs, or credit cards ever leave your network |
| **AI platform operators** | Drop-in reverse proxy with zero code changes to existing OpenAI-compatible APIs |

---

## ✨ Key Features

### ⚡ 3-Layer Defense Architecture

Open-GuardIAn uses a **three-layer security model** — fast heuristics handle 90% of threats deterministically, backed by an optional AI engine for nuanced decisions.

#### Layer 1: DLP Anonymizer — "The Iron Dome" (CPU — Sub-millisecond — Always On)

The DLP layer is the first line of defense. It scans every request for sensitive data and replaces it with **context-preserving anonymizer tokens** that let AI agents understand what type of data was present without exposing the actual values.

| Data Type | Pattern | Anonymizer Token |
|-----------|---------|------------------|
| Email | `user@example.com` | `<EMAIL>` |
| OpenAI Key | `sk-proj-abc123...` | `<KEY>` |
| AWS Key | `AKIA...` | `<AWS_KEY>` |
| GitHub Token | `ghp_...` | `<GITHUB_TOKEN>` |
| Slack Token | `xoxb-...` | `<SLACK_TOKEN>` |
| Groq Key | `gsk_...` | `<KEY>` |
| SSN | `123-45-6789` | `<SSN>` |
| Credit Card | `4111-1111-1111-1111` | `<CC>` |
| IPv4 | `192.168.1.1` | `<IP>` |
| Phone | `+1-555-123-4567` | `<PHONE>` |
| Bearer Token | `Bearer eyJ...` | `<BEARER>` |
| Generic Secret | `api_key=abc123...` | `<SECRET>` |

Each category can be individually toggled on/off via `guardian.toml`:

```toml
[security.dlp]
email_redaction = true
credit_card_redaction = true
secret_redaction = true
ssn_redaction = true
ip_redaction = true
phone_redaction = true
```

#### Layer 2: Heuristic Engine (CPU — Sub-millisecond — Always On)

- **🛡️ Injection Scanner** — Normalization-aware scoring engine:
  - Defeats **accents** (`Tú eres DAN` → `tu eres dan`)
  - Defeats **spacing tricks** (`I g n o r e` → `ignore`)
  - 5 threat categories: Jailbreak, System Prompt Extraction, Roleplay, RCE, Data Exfiltration
  - ~40 weighted patterns with configurable score threshold

- **📋 Threat Engine Signatures** — Modular, internationalized database:
  - **Severity 100 (Block)**: `cat /etc/passwd`, `drop table`, `{{.*}}`, `eval(base64`, `union select`, `system.exit`
  - **Severity 80 (Tag & Audit)**: `rm -rf`, `wget`, `curl`, `chmod`, `exec(`, `whoami` — Agent-First: these are tagged for AI Judge review, not blocked
  - **Severity 70 (Context)**: `hacker`, `malware`, `act as` — signals for context enrichment
  - **Emergency Kit**: Critical patterns hardcoded in the Rust binary — system is **never** unprotected
  - **DevOps Whitelisting**: Explicitly allow `git pull`, `kubectl apply`, etc.
  - **Multilingual**: EN + ES dictionaries, easily extensible

> **Note**: Layer 2 uses advanced normalization-aware heuristics. Unlike heavier BERT models (like PromptGuard), this layer is deterministic, runs in **under 20 microseconds (<20µs)**, and ensures that legitimate traffic passes through with **zero perceptible overhead**.

#### Layer 3: AI Judge — "The Sheriff" (Optional but Recommended)

> [!NOTE]
> **This layer is OPTIONAL.** Open-Guardian provides enterprise-grade security (Layer 1 & 2) even without the AI Judge.

- **🤠 Contextual Intent Analysis** — Uses a local LLM (via Ollama) to decide whether flagged commands are legitimate agent operations or actual attacks
- **Agent-First Philosophy**: `rm -rf /tmp/cache` for cleanup? **SAFE**. `rm -rf /` without context? **UNSAFE**.
- **Model Agnostic**: Defaults to `qwen2.5:0.5b` (fast/light), but **can use ANY model** available in your Ollama library (e.g., `llama3`, `mistral`, `gemma`).
- **RAG-Powered**: The Judge receives similar threat patterns as precedent in its system prompt
- **Performance-Optimized**:
  - `moka` semantic cache — repeat prompts resolved in <1ms
  - `tokio::Semaphore` concurrency control — protects host resources
  - Configurable **fail-open** or **fail-closed** when the AI is unavailable
- **Disable Strategy**: To run heuristics-only, set `ai_judge_enabled = false` in `guardian.toml`.

### 🛣️ Smart Multi-Provider Router

- **Unified Endpoint**: One URL (`http://localhost:8080/v1`) for all your AI needs.
- **Cost & Latency Optimization**: Route bulk tasks to cheaper/faster providers (Groq) and complex reasoning to capable models (GPT-4), controlled entirely by config.
- **Vendor Lock-in Protection**: Swap "gpt-4" to point to "claude-3-opus" in the config without changing a single line of application code.

### 📐 Policy Manager — "The Governor"

Four enforcement modes for every security check:

| Policy | Behavior |
|--------|----------|
| `block` | Return 403 Forbidden — request never reaches the LLM |
| `audit` | Log `WARN` + inject `X-Guardian-Risk: High` header + forward |
| `redact` | Sanitize sensitive data with anonymizer tokens and forward |
| `allow` | No enforcement (not recommended for production) |

---

## 🌐 Smart Routing & Gateway Mode

Open-Guardian is not just a firewall; it is a **Multi-Provider API Gateway**. You can configure a single instance to route traffic to dozens of different providers based on the `model` field in your request.

### 🔀 Dynamic Routing
"Request `gpt-4`? Send to OpenAI."
"Request `llama-3`? Send to Groq for speed."
"Request `mistral`? Send to a local vLLM instance."

All of this happens **transparently** to your client application.

### 🔑 Zero-Trust Key Injection
Client applications **DO NOT** need to handle provider API keys.
1. You set keys in your server's `.env` (e.g., `OPENAI_API_KEY`, `GROQ_API_KEY`).
2. Open-Guardian injects the correct key into the upstream request header based on the destination.
3. This ensures **keys never leak** to client-side agents or logs.

### 🏷️ Model Aliasing
You can define custom model names (aliases) that map to specific provider versions. This allows you to swap underlying models without changing application code.

**Configuration Example (`guardian.toml`):**

```toml
[routes]
# 1. Alias "fast-model" to Llama 3 on Groq
"fast-model" = { url = "https://api.groq.com/openai", model = "llama3-70b-8192", key_env = "GROQ_API_KEY" }

# 2. Standard GPT-4o routing
"gpt-4o" = { url = "https://api.openai.com/v1", key_env = "OPENAI_API_KEY" }

# 3. Secure Local Fallback
"local-judge" = { url = "http://127.0.0.1:11434/v1" }
```

**Client Usage:**
```json
// The client just asks for "fast-model"
POST /v1/chat/completions
{
  "model": "fast-model",
  "messages": [...]
}
// Guardian routes this to Groq with the GROQ_API_KEY automatically.
```

### 🔄 Drop-in Replacement Example

You don't need to change your code logic—just point the `base_url` to Guardian.

```python
# Python (OpenAI SDK) Example
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",  # Point to Guardian
    api_key="sk-dummy"                    # Guardian injects the real key!
)

# Route to Groq automatically by using the alias defined in guardian.toml
response = client.chat.completions.create(
    model="fast-model",
    messages=[{"role": "user", "content": "Hello!"}]
)
# Guardian routes this to Groq, injects the key, and anonymizes the prompt.
```

### 📝 Forensic Audit Logging

- All security events logged in **JSONL** format with timestamps
- Events: `injection_blocked`, `dlp_blocked`, `data_redacted`, `threat_blocked`, `semantic_blocked`
- Easily ingestible by SIEM tools (Splunk, ELK, Datadog)

### 📊 Observability (Rolling Logs)

- **Daily Rotation**: Application logs are automatically rotated and saved to the `logs/` directory (e.g., `open-guardian.YYYY-MM-DD.log`).
- **Non-Blocking I/O**: Logging uses an asynchronous, non-blocking actor system (via `tracing-appender`), ensuring that disk writes never slow down the proxy's core engine.

---

> [!TIP]
> **PRO TIP: HYBRID ARCHITECTURE**
> For maximum performance, use a **Hybrid Setup**: Route your generation traffic to **Groq or OpenAI** (for speed) while keeping the **AI Judge** local on Ollama. This prevents your primary generation GPU from being saturated by security checks and guarantees the fastest possible response times.

---

## 🚀 Quickstart & Installation

Open-Guardian can be run as a **standalone binary** (no installation required) or installed as a **system service** (daemon).

### Option A: 📦 Pre-built Binaries (No Rust Required)

**Ideal for**: Production deployment, DevOps, non-Rust developers.

1. **Download** the latest release for your OS from the [Releases Page](https://github.com/AnthonySmith96/open-guardian/releases).
2. **Unzip** the archive.
3. **Verify** you have the following **REQUIRED** files in the same directory:
    - `open-guardian` (The executable)
    - `guardian.toml` (Configuration file)
    - `.env` (API Keys)
    - `rules/` (Directory containing `common.json`, `jailbreaks_en.json`, etc.) ⚠️ **CRITICAL**: The heuristic engine requires this folder to detect threats.

#### Run (Interactive Mode):
```bash
# Linux/Mac
./open-guardian start

# Windows
.\open-guardian.exe start
```

### Option B: 🛠️ Compiling from Source

**Ideal for**: Rust developers, contributors.

```bash
git clone https://github.com/AnthonySmith96/open-guardian.git
cd open-guardian
# Creates a release binary in ./target/release/
cargo build --release
```

---

## 🏃 Usage & Execution Modes

### 1. Interactive Mode (CLI)

Run the proxy in your terminal foreground. Useful for testing and debugging.

```bash
# Standard Start (uses guardian.toml config)
./open-guardian start

# Verbose Logging (Debug mode)
./open-guardian start --verbose

# Local-Only Mode (Forces all upstream traffic to localhost:11434)
./open-guardian start --local
```

### 2. Service Mode (Daemon) 🤖

Install Open-Guardian as a background service that auto-starts on boot and self-heals on failure.

**Prerequisite**: Ensure `open-guardian`, `guardian.toml`, `.env`, and `rules/` are in your desired install location BEFORE installing the service.

#### 🪟 Windows (Administrator PowerShell)
```powershell
.\open-guardian.exe service install
.\open-guardian.exe service start
.\open-guardian.exe service status
```

#### 🐧 Linux / 🍎 macOS (Sudo)
```bash
sudo ./open-guardian service install
sudo ./open-guardian service start
sudo ./open-guardian service status
```

> [!NOTE]
> **Uninstall**: `open-guardian service stop` then `open-guardian service uninstall`

**Logs:** On Linux, use `journalctl -u open-guardian`. On Windows, check the Event Viewer or the `logs/` directory.

---

## 🏗️ Architecture

graph TD
    User[App / Agent] -->|HTTP Request| Proxy[Open-GuardIAn Proxy :8080]
    
    subgraph "🛡️ Security Pipeline"
        Proxy --> Layer1[Layer 1: DLP Anonymizer]
        Layer1 -->|Redacted| Layer2[Layer 2: Heuristics <20µs]
        
        Layer2 -- "Sev 100 (Critical)" --> Block[⛔ BLOCK 403]
        Layer2 -- "Sev 80 (Suspicious)" --> Layer3Check{AI Judge Enabled?}
        Layer2 -- "Safe Traffic" --> Router[Smart Router]
        
        Layer3Check -- Yes --> Layer3[Layer 3: AI Sheriff qwen2.5]
        Layer3Check -- No --> Audit[⚠️ LOG WARN]
        
        Layer3 -- "Malicious" --> Block
        Layer3 -- "Safe Context" --> Router
        Audit --> Router
    end
    
    subgraph "☁️ Upstreams"
        Router -->|gpt-4o| OpenAI[OpenAI API]
        Router -->|llama-3| Groq[Groq Cloud]
        Router -->|local| Ollama[Local LLM]
    end
    
    style Block fill:#ff4d4d,stroke:#333,stroke-width:2px,color:white
    style Router fill:#4d79ff,stroke:#333,stroke-width:2px,color:white
    style Layer3 fill:#9933ff,stroke:#333,stroke-width:2px,color:white

### Pipeline Flow

1. **Incoming Request** → Rate limiter check
2. **Layer 1 — DLP**: Anonymize PII/secrets with `<TOKEN>` tags, or block if policy = `block`
3. **Layer 2 — Heuristics** (always runs, sub-ms):
   - **Injection Scanner**: Score adversarial patterns → block if score ≥ threshold
   - **Threat Engine**: Match against signature database
     - Sev 100 → **Deterministic Block** (SQLi, SSTI, Data Exfil)
     - Sev 80 → **Tag & Audit** (Risky tools — AI Judge or Agent-First allow)
     - Sev 70 → **Context Signal** (Enrich for AI Judge)
4. **Layer 3 — AI Judge** (runs only if enabled AND risk tags present):
   - Retrieve similar threat patterns (RAG) → check moka cache → acquire semaphore → call LLM
   - **If AI Judge is OFF**: Sev 80 items → LOG WARN + ALLOW (Agent-First philosophy)
5. **Policy Enforcement**: `403 Block` / `Audit + Forward` / `Allow + Forward`

---

## ⚙️ Configuration

### `guardian.toml`

```toml
[server]
port = 8080
default_upstream = "https://api.groq.com/openai"
requests_per_minute = 10000

[security]
audit_log_path = "guardian_audit.jsonl"
block_threshold = 50       # Injection score threshold (0-100)

# DLP per-category toggles
[security.dlp]
email_redaction = true
credit_card_redaction = true
secret_redaction = true
ssn_redaction = true
ip_redaction = true
phone_redaction = true

[security.policies]
default_action = "block"   # block | audit | redact | allow
dlp_action = "redact"      # block | redact
allowed_patterns = ["git pull", "git push", "kubectl get", "kubectl apply"]

# Modular Threat Dictionaries
[[security.dictionaries]]
id = "common"
path = "rules/common.json"
enabled = true

[[security.dictionaries]]
id = "jailbreaks_en"
path = "rules/jailbreaks_en.json"
enabled = true

[[security.dictionaries]]
id = "jailbreaks_es"
path = "rules/jailbreaks_es.json"
enabled = true

[judge]
ai_judge_enabled = true
ai_judge_endpoint = "http://127.0.0.1:11434/api/chat"
ai_judge_model = "qwen2.5:0.5b"     # Fallback: qwen2.5:3b
judge_cache_ttl_seconds = 60
judge_max_concurrency = 4
fail_open = true                 # true = Prioritize reliability

[routes]
"gpt-oss" = { url = "https://api.groq.com/openai", model = "openai/gpt-oss-120b", key_env = "GROQ_API_KEY" }
"llama-4" = { url = "https://api.groq.com/openai", model = "meta-llama/llama-4-maverick-17b-128e-instruct", key_env = "GROQ_API_KEY" }
"gpt-4o" = { url = "https://api.openai.com/v1", key_env = "OPENAI_API_KEY" }
"qwen2.5:0.5b" = { url = "http://127.0.0.1:11434/v1" }
```

### `rules/` Directory (Modular Dictionaries)

Add new languages or categories by creating a JSON file in `rules/` and referencing it in `guardian.toml`. All patterns must be **NORMALIZED** (lowercase, no accents).

**Signature format:**
```json
{
  "signatures": [
    {
      "id": "JB-ES-001",
      "pattern": "olvida tus reglas",
      "category": "Jailbreak",
      "severity": 95,
      "is_regex": false
    }
  ]
}
```

**Severity guide:**
| Severity | Action | Use For |
|----------|--------|---------|
| 100 | **Block always** | SQLi, SSTI, data exfiltration, binary payloads |
| 90-99 | **Block always** | Jailbreaks, prompt leaks, instruction overrides |
| 80-89 | **Tag & Audit** | Risky tools (rm, curl, wget, chmod) — AI Judge decides |
| 70-79 | **Context signal** | Suspicious topics (hacker, malware) — enriches AI Judge |
| 50-69 | **Tag only** | Low-confidence signals |

---

## 🔧 CLI Reference

```bash
# Start the proxy
open-guardian start [--port 8080] [--upstream URL] [--local] [--verbose] [--skip-integrity]

# Security audit — scan for exposed secrets and misconfigurations
open-guardian audit [path]

# Service management (Windows/Linux/macOS)
open-guardian service install    # Install as system service
open-guardian service uninstall  # Remove system service
open-guardian service start      # Start the service
open-guardian service stop       # Stop the service
```

---

## 📁 Project Structure

```
open-guardian/
├── src/
│   ├── main.rs                    # CLI entry point & service management
│   ├── server.rs                  # Axum server & 3-layer pipeline orchestrator
│   ├── proxy.rs                   # Reqwest-based request forwarding
│   ├── config.rs                  # TOML config loader & policy definitions
│   ├── audit.rs                   # Static security analysis
│   ├── banner.rs                  # Terminal UI (colored output)
│   ├── logger.rs                  # Tracing/logging initialization
│   └── security/
│       ├── mod.rs                 # Module exports
│       ├── dlp.rs                 # DLP Anonymizer (PII + Secrets → <TOKEN>)
│       ├── injection_scanner.rs   # Adversarial pattern scoring engine
│       ├── threat_engine.rs       # Signature DB + Emergency Kit + RAG
│       ├── normalizer.rs          # Code-aware text normalization
│       └── judge.rs               # AI Sheriff (qwen2.5:0.5b + moka cache + RAG)
├── guardian.toml                  # Runtime configuration
├── rules/                         # Modular threat dictionaries
│   ├── common.json                # Universal threats (RCE, SQLi, SSTI, Secrets)
│   ├── jailbreaks_en.json         # English jailbreak patterns
│   └── jailbreaks_es.json         # Spanish jailbreak patterns
├── audit_prod.py                  # Production audit script (500-req stress test)
├── Cargo.toml                     # Rust dependencies
├── CONTRIBUTING.md                # Contribution guidelines
└── .env                           # API keys (gitignored)
```

---

## 🧪 Testing

```bash
# Run all unit tests
cargo test

# Current test coverage:
#   ✔ DLP: email, CC, SSN, IPv4, OpenAI key, sk-proj-, GitHub, Slack, Groq
#   ✔ DLP: check_for_violations block mode
#   ✔ Normalizer: lowercase, de-accent, syntax preservation, SSTI, SQL
#   ✔ Threat Engine: Sev 100 blocking, Sev 80 tagging, SSTI regex, whitelisting
#   ✔ Injection Scanner: jailbreak, extraction, RCE, safe input

# Production audit (requires running instance)
python audit_prod.py
```

---

## 🛡️ Security Philosophy

> **"Agent-First. Defense-in-Depth. Secure by Default."**

1. **Agent-First** — We enable Agents to use tools (`curl`, `rm`, `wget`, `chmod`), not block them blindly. The AI Judge differentiates legitimate operations from attacks.
2. **Layered Defense** — Layer 1 (DLP + Regex) works 100% without GPU. Layer 2 (Heuristics) catches obfuscated attacks. Layer 3 (AI Judge) provides contextual intent analysis.
3. **Never Naked** — Even if all `rules/*.json` files are deleted, critical signatures are hardcoded in the Rust binary.
4. **Fail-Safe** — If Layer 3 (AI) is off, Layer 1 & 2 provide "Trylon-level" security. Risky tools get logged, not blocked.
5. **Anonymize, Don't Destroy** — DLP replaces sensitive data with `<EMAIL>`, `<KEY>` tokens that preserve semantic context for AI agents, instead of opaque `[REDACTED]` strings.
6. **Audit Everything** — Every block, redaction, and threat match is logged with full forensic detail.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:
- Setting up your development environment
- Adding threat signatures
- Writing scanner modules
- Submitting pull requests

---

## 📄 License

This project is open source. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with ❤️ in Rust for a safer AI future.</strong><br>
  <em>"The best AI firewall is the one that's always on — and the one that knows the difference between an agent doing its job and an attacker exploiting it."</em>
</p>

## ✍️ Contributors

**Original Author:** Anthony Smith ([@AnthonySmith96](https://github.com/AnthonySmith96)) — founded [CyberIndustree](https://github.com/CyberIndustree), built the original Open-GuardIAn foundation.

**v0.1.2 Contributors:** [HeraAndHades](https://github.com/HeraAndHades) — enterprise security hardening through human-AI collaboration.

### What's New in v0.1.2

This release extends the original architecture with **~5,600 lines of security hardening**:

| Module | Original | This Fork |
|--------|----------|-----------|
| DLP | Basic | Full PII/Secret detection + redaction |
| Injection | Basic patterns | Heuristic scoring (90+ = block) |
| Threat Engine | Signatures | Severity tiers + RAG context |
| HMAC Integrity | ❌ | ✅ Rule file tamper protection |
| Path Security | ❌ | ✅ Directory traversal defense |
| Rate Limiting | ❌ | ✅ Token bucket per-IP |
| Request Smuggling | ❌ | ✅ TE/CL validation |
| Env Security | ❌ | ✅ .env permission checks |
| Unicode Norm | ❌ | ✅ Homograph attack defense |

**Development:** Pair-programmed with [Hera](https://github.com/HeraAndHades) (AI agent) over 12+ hours, 27 test cases, live security validation.

**Status:** Preparing upstream PR to merge enhancements back to original
