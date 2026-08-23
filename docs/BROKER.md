# Action Broker (v0.5)

The Action Broker lets an AI agent run **privileged, allowlisted actions**
(`systemctl restart nginx`, deploy scripts, …) without ever holding a
credential and without any in-band approval the agent could grant itself.

Four gates stand between the agent and the command:

1. **Signed policy** — an ed25519-signed TOML file lists the exact argv the
   agent may ever request. One flipped byte after signing and the daemon
   refuses to start.
2. **Out-of-band approval** — every request needs a human typing the
   6-character approval code in a separate terminal. The code never crosses
   the agent channel.
3. **Chained audit** — every event (requested, approved, executed, delivered)
   lands in a hash-chained JSONL log; `open-guardian verify` detects any edit,
   deletion, or reordering.
4. **Output DLP** — stdout/stderr pass through the same DLP engine as the
   egress proxy: secrets and PII are redacted, obfuscated secrets suppress the
   whole output.

The design borrows proven pieces instead of inventing: the request state
machine follows Teleport's `tsh request` (pending → approve/deny → TTL →
auto-expire), one-time result delivery follows Vault's response-wrapping
semantics (single reader, bounded life), and secrets reach the child process
the 1Password `op run` way — resolved at execution time, injected into the
child's environment only, never returned to the caller.

## Quickstart

```console
# 1. Keypair (secret key stays offline; the .pub is pinned in config)
$ open-guardian policy keygen --key broker/policy.key

# 2. Write broker/policy.toml (see examples/broker-policy.toml), then sign it
$ open-guardian policy sign --policy broker/policy.toml --key broker/policy.key

# 3. Point guardian.toml at both files
$ cat guardian.toml
[broker]
policy = "broker/policy.toml"
public_key = "broker/policy.pub"
audit_log_path = "guardian_broker_audit.jsonl"

# 4. (Unix, elevated actions only) install the generated sudoers rules
$ open-guardian policy sudoers --user "$USER"   # prints /etc/sudoers.d/ lines

# 5. Start the daemon
$ open-guardian broker start
BROKER listening on 127.0.0.1:xxxx (N actions). ...

# 6. From another terminal (the agent side, or a real MCP harness)
$ open-guardian broker request restart-nginx "nightly reload"
✔ Request 4ddbc0b9 created (pending) — awaiting operator approval.

# 7. Operator approves — the code lives ONLY on this channel
$ open-guardian requests
4ddbc0b9  pending  restart-nginx  nightly reload  code: xquupe
$ open-guardian approve 4ddbc0b9 --code xquupe
✔ Request 4ddbc0b9 approved; executing.
  exit_code: 0

# 8. Tamper-evidence
$ open-guardian verify guardian_broker_audit.jsonl
✔ Audit chain OK: 11 events, tip 65f4a916cf45e439
```

## MCP integration (harness-agnostic)

`open-guardian mcp` speaks Model Context Protocol over stdio using the
official Rust SDK, so any MCP client works (Claude Code, Cursor, Goose, …):

```json
{ "mcpServers": { "guardian": { "command": "open-guardian", "args": ["mcp"] } } }
```

Three tools, all agent-channel only:

| Tool | Purpose |
|---|---|
| `guardian_list_actions` | What the signed policy allows |
| `guardian_request_action` | Request one (returns a request id; **never** a code) |
| `guardian_request_status` | Poll; the sanitized result is delivered exactly once |

## Architecture

```
MCP harness ──stdio── open-guardian mcp ──┐
                                          │ loopback HTTP + agent token
                                          ▼
                              open-guardian broker start
                              (daemon, unprivileged user)
                                 ├─ signed policy (ed25519)
                                 ├─ SecretBroker → child env only
                                 ├─ DlpEngine on stdout/stderr
                                 └─ hash-chained audit log
                                          ▲
Operator CLI ─────────────────────────────┘ loopback HTTP + admin token
(approve / deny / requests — the only channel that sees codes)
```

- The daemon binds **127.0.0.1 only** on an ephemeral port. Two bearer tokens
  are written as discovery files (mode 0600) in `$XDG_RUNTIME_DIR`:
  `guardian-broker.json` (agent: request/status) and
  `guardian-broker-admin.json` (operator: everything). The agent token
  physically cannot reach the approve/deny endpoints or the approval codes.
- Requests expire after `pending_ttl_secs` (default 120); results are kept
  `result_ttl_secs` (default 300) and are readable **exactly once** — the
  first reader (operator or agent) consumes them.
- Commands execute with the **exact argv from the policy** — no shell, no
  arguments from the agent. Elevated actions run through
  `sudo -n -u <user> -- <argv>`.
- Secret references (`{{secret:env://…}}`, `{{secret:keychain://…}}`,
  `{{secret:vault://…}}`) resolve inside the daemon at execution time and are
  injected into the child's environment. If any reference fails to resolve,
  **nothing executes**.

## Sudoers (surgical, Unix only)

For each action with `user = "…"`, `open-guardian policy sudoers` prints one
exact-match line:

```
guardian-broker ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx
```

Install with `visudo -f /etc/sudoers.d/guardian-broker`. Run the daemon as a
dedicated unprivileged user (`guardian-broker` above); the broker itself never
needs root. Never allowlist a binary the daemon user can write.

## Threat model — what this does and does not stop

**Stops**: the agent exfiltrating credentials (it only ever sees DLP-sanitized
output), executing anything not in the signed policy, self-approving (the code
never crosses the agent channel), silent history rewriting (hash chain), and
policy tampering (signature).

**Does not stop** (be honest with yourself): an agent that can already execute
arbitrary shell commands **as your user** can read the discovery files and run
`open-guardian approve --yes`. The approval code and the two-token split raise
the bar and make misuse loud (audited, desktop notification, visible in the
daemon log), but the real boundary on a compromised same-user host is the
sudoers rule set and how far `user =` targets reach. Run the daemon under its
own OS user if you need a hard boundary.

**Windows**: the broker works without elevation (`user =` unset). sudo-based
elevation is Unix-only; policies that set `user` refuse to execute on Windows.

## Configuration reference

```toml
[broker]
policy = "broker/policy.toml"        # required (signed)
public_key = "broker/policy.pub"     # required (pinned ed25519 key, hex)
audit_log_path = "guardian_broker_audit.jsonl"
pending_ttl_secs = 120               # approval window
result_ttl_secs = 300                # one-time result retention
```

Policy format (full example in `examples/broker-policy.toml`):

```toml
version = 1

[[action]]
id = "restart-nginx"                 # lowercase kebab-case, unique
description = "Restart nginx"
exec = ["/usr/bin/systemctl", "restart", "nginx"]   # literal argv, no shell
user = "root"                        # optional sudo target
timeout_secs = 30                    # 1..=600
output = "redact"                    # "redact" (default) | "suppress"

[[action.env]]                       # optional, resolved at exec time
name = "DEPLOY_TOKEN"
reference = "{{secret:env://DEPLOY_TOKEN}}"
```

## Audit events

`policy_loaded`, `broker_started`, `action_requested`, `action_approve_rejected`,
`action_approved`, `action_denied`, `action_expired`, `action_executed`
(exit code + duration, never output), `result_delivered`, `broker_stopped` —
each chained with `seq`/`prev`/`hash` fields; `open-guardian verify <file>`
walks and validates the chain.
