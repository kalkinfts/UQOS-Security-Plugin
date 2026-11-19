# UQOS SIG-TD / TTC Router

## Implemented

UQOS now contains an executable Speculative Invariant-Guided Token Drafting (SIG-TD) substrate.

The router computes next-token Shannon entropy and an explicit Formal Verification Complexity (FVC) signal, then selects FAST_NEURAL_BYPASS or APEX_SYMBOLIC_SPECULATION.

## Important correction to the original architecture

The current implementation does not claim to inspect or mutate a transformer KV-cache. A kv_cache_hash is a cryptographic commitment supplied by the model/runtime integration.

Likewise, UNSAT proves that the encoded safety-counterexample query is unsatisfiable under the supplied symbolic model. It does not prove arbitrary generated code is universally correct.

This keeps the substrate usable now while leaving the model-runtime and hardware integration boundaries explicit.

## Runtime flow

logits + FVC + critical-section signal -> TTC router -> K candidate AST fragments -> symbolic projections -> incremental SMT -> reject SAT/unknown candidates -> accept UNSAT candidate -> emit verification evidence hash -> ReceiptChain -> UQOS finality policy -> execution.

Z3 documents push/pop as incremental solver scopes: assertions added under a pushed scope are retracted by pop(). citeturn107665search0turn107665search7

## FVC

FVC is intentionally a runtime signal rather than a claimed universal complexity metric. A production draft model can supply it from AST depth, branching, memory effects, concurrency primitives, solver history, and learned calibration.

Recommended calibration objective: FVC = calibrated P(verification-cost > budget | AST prefix, runtime state).

## E-graph integration

The next adapter boundary is an equality-saturation engine. UQOS retains the same candidate commitment and verifier evidence while an e-graph supplies equivalence-class reductions before SMT.

## Shared-memory integration

For CPU/GPU deployments, use pinned shared buffers or a dedicated IPC ring rather than claiming arbitrary Python objects live in GPU L3/HBM. The protocol requires an immutable candidate snapshot, stable commitment, verifier-visible symbolic delta, and deterministic evidence hash.

## Security rule

Never upgrade UNKNOWN to safe. Only an actual UNSAT result for the encoded counterexample query can produce PROVEN_MODEL_SAFE.

## Monetization

Billable meters: ttc_routed_event, smt_verification_ms, and verified_candidate.

Recommended packaging: Developer 10k routed events free; Pro 1M routed events; Security Pro 5M events plus ReceiptChain; Enterprise custom confidential execution and heterogeneous attestation.

Billing consumes deterministic usage records. Security verification must not depend on payment-provider availability.

## Evidence

Every accepted candidate carries token id, AST hash, KV-cache commitment hash, solver result, checked-candidate count, elapsed verifier time, and evidence hash.

That evidence can be inserted as a ReceiptChain step and associated with the UQOS state hash.