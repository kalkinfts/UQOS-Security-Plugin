# UQOS Security Plugin

Authorized defensive security auditing and evidence tooling for Claude Code.

## What is implemented

- Six executable, allowlisted adapters: nmap, httpx, nuclei, nikto, amass, and subfinder.
- Async subprocess execution with timestamped stdout/stderr JSONL events.
- Bounded execution with a maximum 300-second timeout.
- Dry-run by default; public-target active execution requires UQOS_AUTH_TOKEN and an exact hostname entry in UQOS_AUTHORIZED_TARGETS.
- Backend selection across native, verified WSL, and explicitly configured local Docker/Podman images.
- Result attestation using BLAKE3 when the Python blake3 package is installed, otherwise SHA-256.
- SHA-256 chained audit records.

This is an extensible adapter architecture, not a claim that 183 tools are currently integrated. Only the six adapters listed above are currently allowlisted and implemented.

## ReceiptChain v3

The repository includes an additive SQLite-backed proof-carrying receipt ledger with atomic fencing, zero-step rejection, SHA-512 attestation binding, and RFC 6962 inclusion proofs. See docs/RECEIPTCHAIN_V3.md.

The platform quote verifier and transparency-checkpoint signature verifier are injected trust roots. The fixture tests do not claim real Intel TDX hardware attestation.

## Stateful Bi-Directional Streaming Substrate

plugins/uqos-security/scripts/uqos_stream.py provides continuous synchronization with deterministic state versions, SHA-256 state hashes, predecessor chaining, idempotency keys, and optimistic concurrency checks. uqos_run.py attaches live state hashes to streamed security output and creates ReceiptChain receipts for executed runs.

The production transport can be Supabase Realtime Broadcast, WebSockets, or another CDC/webhook transport. See docs/STATEFUL_STREAMING.md.

## Refereed Silicon Execution

plugins/uqos-security/scripts/refereed_silicon.py implements the buildable-now protocol boundary for:

- pre-committed execution segments;
- verifier-randomness spot checks;
- heterogeneous TDX/SEV-SNP/Arm CCA quorum policy;
- attested, proven, and settled finality;
- GKR/sumcheck/Freivalds-style verifier integration hooks;
- future Poseidon2 RTMR and hardware-memory-root interfaces.

See docs/REFEREED_SILICON_EXECUTION.md.

## SIG-TD Test-Time Compute Router

plugins/uqos-security/scripts/sig_td_ttc.py adds entropy/FVC-routed speculative symbolic verification.

Flow:

logits + FVC + critical-section signal -> TTC routing -> candidate AST branches -> incremental Z3 SMT -> reject SAT/unknown branches -> accept UNSAT model-safe branch -> evidence hash -> ReceiptChain/UQOS finality.

Z3 officially supports incremental push/pop scopes, making the persistent solver model appropriate for this boundary. citeturn107665search0turn107665search7

Important trust boundary: kv_cache_hash is currently a cryptographic commitment supplied by the model/runtime. It is not direct access to a transformer KV cache. UNSAT proves the encoded counterexample query is unsatisfiable under the supplied symbolic model; it does not prove arbitrary code universally correct.

Install the SIG-TD runtime:

    python -m pip install -r plugins/uqos-security/requirements-sig-td.txt

See docs/SIG_TD_TTC.md.

## Monetization

The UQOS substrate exposes deterministic usage meters. The SIG-TD extension adds:

- ttc_routed_event
- smt_verification_ms
- verified_candidate

Recommended packaging:

| Tier | Allowance | Value |
|---|---:|---|
| Developer | 10k routed events/month | Free |
| Pro | 1M routed events/month | TTC routing + SMT |
| Security Pro | 5M events/month | ReceiptChain + proven candidates |
| Enterprise | Custom | confidential execution + heterogeneous attestation |

Billing consumes exported usage records and remains decoupled from security verification.

## Install

    /plugin marketplace add kalkinfts/UQOS-Security-Plugin
    /plugin install uqos-security@uqos-security-marketplace

## Run

Dry-run:

    python plugins/uqos-security/scripts/uqos_run.py --tool nmap --target 127.0.0.1

Authorized active check:

    UQOS_AUTH_TOKEN=<your-authorization-token> UQOS_AUTHORIZED_TARGETS=example.com python plugins/uqos-security/scripts/uqos_run.py --tool nmap --target 127.0.0.1 --execute

## Verify

    python -m compileall plugins
    python -m pytest -q

Use only against systems you own or are explicitly authorized to assess. No bypassing authorization, credential theft, malware deployment, evasion, or disruption.
