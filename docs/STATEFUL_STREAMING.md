# UQOS Stateful Bi-Directional Event-Driven Streaming

## What is implemented

UQOS now has a transport-neutral **Stateful Streaming Substrate**:

- `uqos_stream.py` maintains a deterministic state snapshot.
- Every accepted event receives a monotonic sequence, state version, SHA-256 state hash and chained predecessor hash.
- Inbound and outbound events use the same state ledger, making the stream genuinely bi-directional.
- `expected_state_hash` provides optimistic concurrency control. A stale mutation is rejected before commit.
- `idempotency_key` makes duplicate delivery replay-safe.
- `uqos_substrate.py` composes the ledger with ReceiptChain v3 and usage metering.
- `uqos_run.py` now emits live state hashes for scanner output and creates a ReceiptChain receipt for executed runs.

## Important trust boundary

A state hash proves that two software components agreed on a canonical state representation. It does **not** prove that an LLM's private KV-cache was externally mutated, and it does not constitute hardware attestation.

ReceiptChain v3 therefore keeps TDX verification fail-closed. The runner's default development attestation is explicitly labeled `development-receipt` and is not accepted as hardware-verified evidence. Production deployments must inject a trusted quote verifier.

## Event flow

External system -> webhook/CDC -> UQOS inbound queue -> state ledger -> hash-checked mutation -> UQOS outbound event -> consumer/agent -> ReceiptChain step -> usage meter.

For Supabase, the preferred production transport is Realtime Broadcast with private-channel authorization. Supabase documents Broadcast as the recommended scalable/security option and supports database-triggered broadcasts; Database Webhooks can separately send INSERT/UPDATE/DELETE payloads to external systems.

## Monetization

The code exposes deterministic usage records instead of embedding payment secrets:

- `stream_event`: one metered event.
- `stream_bytes`: payload bytes associated with streamed events.
- `verified_receipt`: reserved for production attestation-backed receipts.

Recommended product tiers:

| Tier | Included | Monetization |
|---|---:|---|
| Developer | 10k events/month | Free |
| Pro | 1M events/month | Monthly subscription + overage |
| Security Pro | 5M events/month + ReceiptChain evidence | Higher monthly subscription |
| Enterprise | Custom | Contract / usage |

The `UsageMeter` export is intentionally provider-neutral; Stripe/Metronome or another billing provider can consume the exported meter without coupling security state to payment state.

## Local verification

    python -m compileall plugins/uqos-security/scripts plugins/uqos-security/tests
    python -m pytest plugins/uqos-security/tests -q

The GitHub workflow executes the regression suite on every push/PR.
