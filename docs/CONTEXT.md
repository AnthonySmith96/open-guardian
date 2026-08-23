# Context DLP (v0.6)

The egress proxy guards what leaves the machine; the Action Broker guards
what the agent *executes*. **Context DLP** guards what enters the model's
context: tool output is sanitized by the same DLP engine before the harness
ever sees it.

```
harness ──stdio JSON-RPC──► open-guardian mcp-gateway ──► any MCP server
harness ◄──sanitized──────── open-guardian mcp-gateway ◄── tool results
```

## The two surfaces

### 1. `mcp-gateway`: wrap any MCP server

`open-guardian mcp-gateway` spawns a downstream MCP stdio server and pipes
the harness through it. Harness → downstream traffic is forwarded verbatim;
on the way back, every **tool result** (the JSON-RPC `CallToolResult` shape)
is sanitized before it reaches the model. Requests, notifications,
`tools/list`, resources, prompts, and sampling pass through untouched — the
gateway is invisible to both ends.

```console
$ open-guardian mcp-gateway -- npx -y @modelcontextprotocol/server-github
```

Harness config (Claude Code / any stdio-capable harness):

```json
{
  "mcpServers": {
    "github": {
      "command": "open-guardian",
      "args": ["mcp-gateway", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

`--rules <file>` swaps in another rules file (gitleaks format), like `bench`.
It must appear **before** the `--` separator.

The gateway exits with the downstream server's exit code; closing the
harness session closes the downstream's stdin, ending it.

### 2. `sanitize`: a filter for everything else

`open-guardian sanitize` runs stdin through the engine and prints the result
to stdout — for harness hooks, shell pipelines, and logs:

```console
$ cat .env.production | open-guardian sanitize
STRIPE_KEY=<STRIPE-KEY>
$ curl -s https://api.example.com/status | open-guardian sanitize
$ open-guardian sanitize --file dump.txt
```

Status messages go to stderr; stdout stays pipe-clean.

## What "sanitized" means

Identical to the broker's output rule — one pipeline, three outcomes:

1. **Plain secrets/PII** (API keys, cards, emails, phones, …) are **redacted
   in place, irreversibly**: `sk_live_Qw…` becomes `<STRIPE-KEY>`. The model
   keeps the structure of the output, never the value.
2. **Obfuscated secrets** (percent/double-percent encoding, HTML entities,
   zero-width characters, homoglyphs — anything that only surfaces after
   normalization) **cannot be rewritten in place, so the whole output
   suppresses**: `[output suppressed: potential obfuscated sensitive data
   detected]`. Fail-closed, corpus-proven (see docs/BENCHMARK.md).
3. **Clean output passes unchanged**, byte for byte.

For tool results, redaction walks the entire `result` tree: `content[].text`
and every string inside `structuredContent`, nested at any depth. JSON
**numbers are probed too** — a bare-digit Luhn card serializes as a number —
and replaced with their redacted form when redaction changes them.

## Threat model (honest)

- **Protects the context** from secrets and PII in tool output: a file
  reader, a `curl`, a database client, or an MCP server that echoes
  credentials no longer pastes them into the conversation.
- **Not a boundary against a malicious downstream.** The wrapped server runs
  as your user with your files; if it is compromised, it can exfiltrate
  through its own channels. Use it against *accidental* leakage from
  legitimate tools.
- **Same trust domain as the harness.** Anything that can run the gateway can
  also run the downstream directly; Context DLP is a safety net for the
  context window, not an access-control system (that is the Action Broker's
  job).
- Binary content blocks (images, audio) pass through untouched — only text
  values and JSON numbers are inspected.
- Egress (what crosses the wire to providers) remains the proxy's job;
  Context DLP covers the surface the proxy never sees: local tool output.

## Rule files

Context DLP loads the same `[security.dlp]` configuration as the proxy and
the broker (`guardian.toml`), rules files included. Missing or invalid rule
files are fatal — fail-closed, like everywhere else. `--rules` on the CLI
overrides them for one invocation.
