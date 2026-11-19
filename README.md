# UQOS Security Plugin

Authorized defensive security auditing and evidence tooling for Claude Code.

## SIG-TD / TTC

The UQOS SIG-TD substrate provides entropy/FVC-routed speculative symbolic verification.

Flow:

logits + FVC + critical-section signal -> TTC routing -> candidate AST branches -> incremental Z3 SMT -> reject SAT/unknown -> accept UNSAT model-safe branch -> evidence hash -> ReceiptChain/UQOS finality.

Native Rust path: plugins/uqos-security/native/

- Rust Z3 verification
- egg equality saturation
- bounded SMT-LIB2 candidate deltas
- deterministic candidate/evidence commitments
- native regression tests

The Rust ecosystem provides an idiomatic z3 wrapper plus lower-level z3-sys bindings; egg provides Rust equality-saturation e-graphs. citeturn170050search4turn170050search0turn170050search2

## Neural-symbolic projection

scripts/neural_symbolic_projection.py defines the inference boundary for a future LoRA/draft-model projection head:

vocabulary logits + SMT-LIB2 delta + KV commitment

The boundary validates payload size, approved SMT forms, probability range and SHA-256 commitments.

This is an inference contract, not a claim that a production projection model has already been trained.

## eBPF critical-infrastructure gate

scripts/verify_ebpf_artifact.py compiles an eBPF artifact and refuses to call it verified when the authoritative kernel verification path is unavailable.

Linux's eBPF verifier performs control-flow checks and state simulation and tracks register, stack, pointer bounds and initialization. citeturn170050search1turn170050search11

UQOS composes with the kernel verifier instead of replacing it.

## Empirical deployment

draft -> SIG-TD -> e-graph -> SMT/model verification -> ReceiptChain -> domain verifier -> staged execution -> telemetry -> promotion

CPU affinity, pinned memory and hugepages are optimization controls, not proof assumptions. GPU HBM and CPU L3 are distinct memory domains.

See docs/SIG_TD_EMPIRICAL_DEPLOYMENT.md.

## Existing UQOS layers

- ReceiptChain v3
- Stateful Bi-Directional Streaming
- Refereed Silicon Execution
- SIG-TD TTC
- deterministic monetization meters

## Monetization

Meters:

- ttc_routed_event
- smt_verification_ms
- verified_candidate

Packaging:

| Tier | Allowance | Value |
|---|---:|---|
| Developer | 10k routed events/month | Free |
| Pro | 1M routed events/month | TTC routing + SMT |
| Security Pro | 5M events/month | ReceiptChain + proven candidates |
| Enterprise | Custom | confidential execution + heterogeneous attestation |

Billing remains decoupled from security verification.

## Install

/plugin marketplace add kalkinfts/UQOS-Security-Plugin
/plugin install uqos-security@uqos-security-marketplace

Python runtime:
python -m pip install -r plugins/uqos-security/requirements-sig-td.txt

Native runtime:
cargo test --manifest-path plugins/uqos-security/native/Cargo.toml

Use only against systems you own or are explicitly authorized to assess.
