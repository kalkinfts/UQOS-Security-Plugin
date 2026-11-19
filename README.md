# UQOS Security Plugin

Authorized defensive security auditing and evidence tooling for Claude Code.

## What is implemented

- Six executable, allowlisted adapters: `nmap`, `httpx`, `nuclei`, `nikto`, `amass`, and `subfinder`.
- Async subprocess execution with timestamped stdout/stderr JSONL events.
- Bounded execution with a maximum 300-second timeout.
- Dry-run by default; public-target active execution requires `UQOS_AUTH_TOKEN` **and** an exact hostname entry in `UQOS_AUTHORIZED_TARGETS`.
- Backend selection across native, verified WSL, and explicitly configured local Docker/Podman images.
- Result attestation using BLAKE3 when the Python `blake3` package is installed, otherwise SHA-256. The output always names the algorithm used.
- SHA-256 chained audit records.

This is an extensible adapter architecture, **not a claim that 183 tools are currently integrated**. Only the six adapters listed above are currently allowlisted and implemented. Additional tools require an adapter, safety policy, tests, and documentation before they can be described as supported.

## ReceiptChain v3

The repository now includes an additive SQLite-backed proof-carrying receipt ledger with atomic fencing, zero-step rejection, SHA-512 attestation binding, and RFC 6962 inclusion proofs. See [docs/RECEIPTCHAIN_V3.md](docs/RECEIPTCHAIN_V3.md) for the trust boundary, API sequence, and test command.

The platform quote verifier and transparency-checkpoint signature verifier are intentionally injected trust roots. The included fixture tests do not claim real Intel TDX hardware attestation.

## Stateful Bi-Directional Streaming Substrate

`plugins/uqos-security/scripts/uqos_stream.py` adds a transport-neutral continuous synchronization layer. External events and UQOS outbound mutations share one deterministic state ledger with monotonic versions, SHA-256 state hashes, predecessor chaining, idempotency keys, and optimistic concurrency checks. `uqos_run.py` now attaches live state hashes to streamed security output and creates a ReceiptChain receipt for executed runs.

The production transport can be Supabase Realtime Broadcast, WebSockets, or another CDC/webhook transport. Supabase currently recommends Realtime Broadcast for scalable secure database change delivery and documents Database Webhooks for asynchronous INSERT/UPDATE/DELETE delivery. See [docs/STATEFUL_STREAMING.md](docs/STATEFUL_STREAMING.md).

**Trust boundary:** a state hash proves synchronization of a canonical software state representation. It does not mean external systems can directly mutate an LLM's private KV-cache, nor does it constitute hardware attestation. The runner's default receipt attestation is explicitly development-only and must be replaced by a trusted TDX quote verifier for production hardware-backed evidence.

## Monetization substrate

`uqos_substrate.py` exposes deterministic usage records for `stream_event`, `stream_bytes`, and production `verified_receipt` metering. This keeps billing provider-neutral and prevents payment secrets from entering the security substrate. A recommended free/pro/security-pro/enterprise packaging is documented in `docs/STATEFUL_STREAMING.md`.

## Install

```text
/plugin marketplace add kalkinfts/UQOS-Security-Plugin
/plugin install uqos-security@uqos-security-marketplace
```

## Run

Dry-run (default):

```bash
python plugins/uqos-security/scripts/uqos_run.py --tool nmap --target 127.0.0.1
```

Authorized active check:

```bash
UQOS_AUTH_TOKEN=<your-authorization-token> UQOS_AUTHORIZED_TARGETS=example.com python plugins/uqos-security/scripts/uqos_run.py --tool nmap --target 127.0.0.1 --execute
```

Output is newline-delimited JSON: an execution-start event, zero or more stdout/stderr events, and a final structured result with its attestation. Active public-target execution requires an operator-supplied token and an exact hostname in `UQOS_AUTHORIZED_TARGETS` (comma-separated). This is an operator-enforced scope gate, not an external verification of ownership or a cryptographic authorization service.

For container fallback, configure a local image, for example `UQOS_IMAGE_NMAP=nmap-local:latest`; the image must already exist locally. The runner does not pull arbitrary images.

## Verify

```bash
python -m compileall plugins
python -m pytest -q
```

Use only against systems you own or are explicitly authorized to assess. No bypassing authorization, credential theft, malware deployment, evasion, or disruption.
