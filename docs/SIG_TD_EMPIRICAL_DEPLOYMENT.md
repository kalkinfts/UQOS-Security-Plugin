# Empirical SIG-TD Deployment Path

## Status

The UQOS implementation now has three concrete runtime boundaries:
1. **Native Rust verifier:** `plugins/uqos-security/native`
2. **Neural-symbolic projection contract:** `scripts/neural_symbolic_projection.py`
3. **eBPF fail-closed verification gate:** `scripts/verify_ebpf_artifact.py`

## 1. Native SMT/e-graph path

The Rust crate uses `z3` for the idiomatic Rust API and `egg` for equality saturation. The Z3 Rust ecosystem also exposes `z3-sys` for raw C-API FFI when lower-level control is required. `egg` is specifically designed for equality saturation and program optimization/synthesis. citeturn170050search4turn170050search0turn170050search2

The native verifier receives: `Candidate = token_id + AST fragment + logit + SMT-LIB2 delta + KV commitment` and emits deterministic verification evidence.

The KV field remains a commitment. The verifier does not falsely claim direct access to a transformer KV cache.

## 2. Projection head

A future LoRA/draft-model head emits: `vocab_logits + SMT-LIB2 delta + KV commitment`. The UQOS boundary validates maximum symbolic payload size, allowed top-level SMT forms, no NUL bytes, probability range, and SHA-256 KV commitment.

Recommended training target: `L = L_token + λ_fvc L_fvc + λ_smt L_valid + λ_safe L_invariant`.

## 3. Shared memory

Do not claim that CPU L3 is shared with GPU HBM. They are distinct memory domains. Use a pinned host-memory ring / DMA-capable buffer where supported, or explicit IPC/shared-memory segments. The protocol requires immutable candidate buffers and commitments, not a particular memory topology.

## 4. eBPF

Linux already provides a kernel eBPF verifier. It performs CFG checks and state simulation, tracks register/stack state, pointer bounds and initialization, and prunes equivalent verifier states. citeturn170050search1turn170050search11

UQOS therefore treats the kernel verifier as the final authority for eBPF safety rather than replacing it. The UQOS gate compiles the artifact and refuses to represent a non-verified artifact as deployable.

## 5. Critical infrastructure

The production sequence is: `draft → SIG-TD → e-graph normalization → SMT/model verification → ReceiptChain → domain verifier → staged execution → observed telemetry → promotion`.

For eBPF, the domain verifier is the Linux kernel verifier. For other critical systems, the domain verifier must be the platform's authoritative safety mechanism.

No system should claim that SIG-TD alone makes arbitrary generated software mathematically safe.

## 6. Hardware acceleration

Dedicated CPU cores and pinned memory are deployment optimizations, not proof assumptions. Use CPU affinity only after measurement. Verifier evidence must remain identical regardless of core placement.

Optimization boundary: Rust native verifier; bounded SMT-LIB2 delta; e-graph reduction; lock-free candidate ring; CPU affinity; optional hugepages; model-runtime integration.

## 7. Security posture

`UNKNOWN`, timeout, malformed symbolic delta, failed e-graph parse, missing kernel verifier, and failed attestation are all **non-final** states.

Only an explicitly configured domain verifier can advance a candidate to the next finality tier. This preserves the UQOS ReceiptChain trust boundary.