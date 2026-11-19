# UQOS Refereed Silicon Execution

This layer turns the proposed refereed-silicon architecture into a concrete protocol boundary.

## 1. ZK-native measurement registers — hardware request

Current Intel TDX RTMRs are SHA-384 based and are included in TDX attestation evidence. Intel's current TDX documentation does not expose a native Poseidon2 RTMR or a CPU-derived algebraic memory root. UQOS therefore models both as explicit future-silicon interfaces rather than pretending they exist.

Interfaces:
- PoseidonRTMRHardware.extend_sha384_poseidon2(...)
- HardwareMemoryRoot.memory_root()

A silicon vendor could implement these without changing the UQOS higher-level protocol.

## 2. Hardware-derived state root — hardware request

UQOS accepts a future hardware memory-root capability as an additional evidence source. Until a platform actually supplies such a root, the protocol uses software commitments and TDX measurements without upgrading their security claim.

## 3. Verifier-randomness spot checks — buildable now

Execution segments are committed before challenge selection.

1. Build segment digests.
2. Commit the ordered segment list.
3. Obtain a beacon value that was not predictable when the commitment was made.
4. Derive challenge indices from beacon || commitment.
5. Require a zkVM/proof verifier to answer those exact challenges.
6. Advance from attested to proven only after verification.

The reference implementation includes deterministic CI verification. Production should replace the reference verifier with the selected zkVM proof system and an authenticated public randomness beacon.

For a cheated fraction p and k independent samples, the basic detection probability is 1-(1-p)^k. This is a probability model, not a claim of absolute security.

## 4. Heterogeneous quorum — buildable now

HeterogeneousQuorum accepts multiple independent attestation roots:
- Intel TDX
- AMD SEV-SNP
- Arm CCA

The policy can require a threshold, e.g. 2 of 3, rather than treating any single vendor as sufficient.

Important: a quorum improves defense in depth; it does not mathematically prove independence between vendor implementations.

## Verifiable AI at line rate

VerifiableMatmulVerifier is a protocol hook for GKR/sumcheck/Freivalds-style inference verification. The UQOS protocol derives its challenge seed from committed execution state rather than allowing a prover to choose favorable challenges.

Actual inference proofs remain workload/model dependent and must be supplied by a real prover/verifier implementation.

## Tiered finality

UQOS now distinguishes:
- ATTESTED — hardware attestation/quorum accepted.
- PROVEN — attested frontier plus successful challenge/proof verification.
- SETTLED — policy explicitly permits irreversible settlement.

Example policy:
- reads / small actions → ATTESTED
- large trades / settlement / state commits → PROVEN
- irreversible settlement → SETTLED after explicit policy check

This provides the real-time behavior requested without pretending that instant hardware attestation is equivalent to a completed zk proof.

## Intel boundary

Intel documents that a TDX Quote is generated from hardware and that verification includes the Intel-rooted quote signature chain, TCB status, TD measurements and expected report data. Intel also documents RTMR0-3 as runtime measurement registers. Those facts are the trust anchor for the TDX adapter; UQOS does not fabricate them.
