# ADR-0002: Keep axum + reqwest as the network foundation; revisit rama at transparent interception

- Status: Accepted
- Date: 2026-08-30
- Owners: Open-Guardian maintainers

## Context

Open-Guardian was approached with a proposal to replace its network foundation with
[rama](https://ramaproxy.org), a general-purpose proxy framework, on the premise that Open-Guardian
is "using a client + server framework to duct-tape its own proxy-like network stack." The approach
also included an offer of a commercial service contract. This ADR records
the evaluation so the question does not have to be re-litigated on the next approach, and so the one
condition that would change the answer is written down.

The premise does not match the code. Open-Guardian is not a general-purpose proxy. It is a loopback
reverse proxy for a single application protocol — the OpenAI-compatible HTTP API — and the transport
layer is deliberately thin:

- `src/server.rs` binds a `tokio::net::TcpListener` and serves an axum `Router` with one catch-all
  route (`/*path`) plus `/health`.
- `src/proxy.rs` forwards the request upstream with a `reqwest::Client` and inspects the response.
- There is no `CONNECT` handling, no SOCKS, no TLS termination, no MITM, no HTTP/2 or WebSocket
  upgrade path. The listener speaks plaintext HTTP on loopback by design.

That is roughly 150 lines of genuine transport code out of ~11k in `src/`. The remainder — the DLP
engine and nonce-scoped reversible redaction (`src/security/`), the signed-policy action broker
(`src/broker/`), the hash-chained audit log, the secret backends, and the regression-gated leak
benchmark (`src/bench.rs`) — is domain logic that no network framework supplies.

The hardening that does live near the network edge (request-smuggling header checks in
`src/security/smuggling.rs`, path-traversal rejection, per-IP token-bucket rate limiting in
`src/security/rate_limit.rs`) is already written, tested, and covered by the benchmark gate. A
framework migration would replace working, audited code with an equivalent, not add a capability.

## Decision

The network foundation stays **axum (server) + reqwest (upstream client)** on tokio.

rama is not adopted at this time. No commercial engagement is entered into. Open-Guardian is
Apache-2.0 with no commercial arm, and the offered contract addresses a need the project does not
have.

## Why not migrate now

**No functional gain.** Nothing Open-Guardian does today, or is blocked on doing, is limited by axum
or reqwest. The migration is a rewrite of the handler and forwarding layer for parity.

**MSRV cost.** rama 0.4.0 declares `rust-version = 1.96.0` and edition 2024. Open-Guardian declares
`rust-version = "1.88"`. Adopting rama raises the floor eight releases and cuts off users installing
via `cargo install` on older toolchains, for no user-visible benefit.

**Pre-1.0 churn on a security core.** rama is at 0.4.0 (2026-08-19), after 0.3.0 (2026-07-07) and a
run of `0.3.0-alpha.*` before that — breaking releases roughly every six to eight weeks. Open-Guardian
gates every change on a leak-regression benchmark; putting the request path on an API that reshapes
itself at that cadence adds maintenance surface directly beneath the security boundary.

**Dependency surface.** The lockfile already carries 471 crates. rama's full feature set is far wider
than the one protocol this project proxies.

**Contributor familiarity.** axum and reqwest are the ecosystem default. The proxy handler should be
readable by anyone reviewing a security-sensitive change without first learning a framework.

## What rama does not solve

The README's "Not streaming" limitation is a DLP-boundary decision, not a transport limitation:
responses (including SSE) are buffered to a bounded size so a secret cannot be split across chunk or
event boundaries and slip through inspection. A different network framework does not unblock
token-by-token streaming. That requires a protocol design in which incremental output can be
inspected safely.

## Revisit trigger

There is one milestone that would make rama the right tool rather than a lateral move: **transparent
egress interception**.

Today the guarantee has a known hole recorded in the threat model — an agent that simply does not
point at `http://127.0.0.1:8080/v1` bypasses Open-Guardian entirely. Closing it means intercepting
traffic the client did not opt into: `CONNECT` handling plus MITM with a locally trusted CA and
dynamic certificate generation, or transparent/SNI-based interception. That is exactly rama's
declared core (MITM, transparent, SNI and SOCKS5 proxies; rustls and BoringSSL backends; dynamic
certificates; ACME), and it is a large, security-critical body of work that is a poor candidate for
hand-rolling.

If Open-Guardian takes on transparent interception, this ADR should be superseded by an evaluation of
rama against that specific scope, covering at minimum:

1. Whether rama has reached 1.0 or otherwise offers a stability commitment by then.
2. The MSRV floor at that time versus the project's support policy.
3. Whether interception is confined to a separable component, so the existing loopback reverse proxy
   and the DLP/broker core do not inherit the dependency.
4. Whether the local-CA trust model is acceptable for a tool whose premise is that the operator's
   machine is the trust boundary.

## Rejected alternatives

### Migrate the whole proxy to rama now

Rejected. Parity rewrite, higher MSRV, pre-1.0 API churn under a security-critical path, no capability
gained.

### Adopt rama only for the upstream client, replacing reqwest

Rejected. reqwest is not a constraint here: the upstream call is a single JSON or SSE request to a
configured HTTPS endpoint. Splitting the stack across two frameworks costs clarity for nothing.

### Enter the offered service contract

Rejected. The project has no commercial value to protect and no migration to fund. Community channels
remain available if the transparent-interception work starts.

## References

- rama: <https://github.com/plabayo/rama>, <https://ramaproxy.org>
- rama 0.4.0 on crates.io — MSRV 1.96.0, edition 2024, MIT OR Apache-2.0
- Threat model and non-goals: `README.md`
- Transport touchpoints: `src/server.rs`, `src/proxy.rs`
