"""UQOS Refereed Silicon Execution substrate.

Buildable-now components:
  * challenge-window spot checking with public/unpredictable randomness
  * heterogeneous attestation quorum policy
  * tiered attested/proven finality
  * transcript commitments and deterministic challenge derivation
  * verifier hooks for zkVM/GKR/Freivalds-style proof systems

Hypothetical silicon features are represented only as explicit capability
interfaces (Poseidon2 RTMR and hardware memory roots); this module never
claims they exist on current Intel TDX hardware.

The security model is:
  attested frontier = hardware-backed evidence accepted by policy
  proven frontier  = evidence additionally checked by proof/spot-check policy
  settlement       = policy-controlled minimum finality tier
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, Sequence


def cj(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def h(value: Any) -> str:
    return hashlib.sha256(cj(value)).hexdigest()


def derive_challenge(beacon: bytes, commitment: str, segment_count: int, sample_count: int) -> tuple[int, ...]:
    if segment_count <= 0 or sample_count <= 0:
        return ()
    k = min(segment_count, sample_count)
    chosen: set[int] = set()
    counter = 0
    while len(chosen) < k:
        digest = hashlib.sha256(beacon + bytes.fromhex(commitment) + counter.to_bytes(8, "big")).digest()
        chosen.add(int.from_bytes(digest, "big") % segment_count)
        counter += 1
    return tuple(sorted(chosen))


def detection_probability(cheated_fraction: float, samples: int) -> float:
    if not 0 <= cheated_fraction <= 1 or samples < 0:
        raise ValueError("invalid probability inputs")
    return 1.0 - (1.0 - cheated_fraction) ** samples


class Finality(str, Enum):
    ATTESTED = "attested"
    PROVEN = "proven"
    SETTLED = "settled"


@dataclass(frozen=True)
class Segment:
    index: int
    digest: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class SegmentCommitment:
    root: str
    segment_count: int
    segment_digests: tuple[str, ...]


@dataclass(frozen=True)
class Challenge:
    beacon_id: str
    beacon: bytes
    commitment: str
    indices: tuple[int, ...]


class ProofVerifier(Protocol):
    def verify(self, proof: dict[str, Any], challenge: Challenge) -> bool: ...


class HardwareAttestation(Protocol):
    vendor: str

    def verify(self, evidence: dict[str, Any], expected_report_data: str) -> bool: ...


@dataclass(frozen=True)
class AttestationResult:
    vendor: str
    verified: bool
    evidence_id: str


@dataclass
class HeterogeneousQuorum:
    required_vendors: frozenset[str]
    threshold: int
    allow_debug: bool = False

    def accept(self, attestations: Sequence[AttestationResult]) -> bool:
        valid = {
            a.vendor for a in attestations
            if a.verified and (self.allow_debug or not a.evidence_id.startswith("debug:"))
        }
        return len(valid & self.required_vendors) >= self.threshold


@dataclass
class RefereedExecution:
    execution_id: str
    segments: list[Segment]
    attestation: list[AttestationResult]
    quorum: HeterogeneousQuorum
    report_data: str
    commitment: SegmentCommitment | None = None
    challenge: Challenge | None = None
    proof_verified: bool = False
    finality: Finality = Finality.ATTESTED
    metadata: dict[str, Any] = field(default_factory=dict)

    def commit_segments(self) -> SegmentCommitment:
        digests = tuple(s.digest for s in self.segments)
        root = h({"schema": "uqos.segment.commitment.v1", "segments": digests})
        self.commitment = SegmentCommitment(root, len(digests), digests)
        return self.commitment

    def establish_attested_frontier(self) -> bool:
        if self.commitment is None:
            raise RuntimeError("segments must be committed before attestation")
        expected = h({
            "schema": "uqos.refereed.report-data.v1",
            "execution_id": self.execution_id,
            "segment_root": self.commitment.root,
            "segment_count": self.commitment.segment_count,
        })
        if not hmac.compare_digest(expected, self.report_data):
            return False
        if not self.quorum.accept(self.attestation):
            return False
        self.finality = Finality.ATTESTED
        return True

    def open_challenge(self, beacon_id: str, beacon: bytes, samples: int) -> Challenge:
        if self.commitment is None:
            raise RuntimeError("segments must be committed before challenge")
        indices = derive_challenge(
            beacon, self.commitment.root, self.commitment.segment_count, samples
        )
        self.challenge = Challenge(beacon_id, beacon, self.commitment.root, indices)
        return self.challenge

    def verify_spot_check(
        self,
        proof: dict[str, Any],
        verifier: ProofVerifier,
    ) -> bool:
        if self.challenge is None or self.commitment is None:
            raise RuntimeError("challenge must be opened first")
        if proof.get("commitment") != self.commitment.root:
            return False
        if tuple(proof.get("indices", ())) != self.challenge.indices:
            return False
        self.proof_verified = bool(verifier.verify(proof, self.challenge))
        if self.proof_verified:
            self.finality = Finality.PROVEN
        return self.proof_verified

    def settle(self, *, require_proven: bool = True) -> bool:
        if not self.established_attested():
            return False
        if require_proven and not self.proof_verified:
            return False
        self.finality = Finality.SETTLED
        return True

    def established_attested(self) -> bool:
        return self.commitment is not None and self.quorum.accept(self.attestation)


@dataclass(frozen=True)
class ExecutionPolicy:
    settlement_requires_proven: bool = True
    attested_actions: frozenset[str] = frozenset({"read", "small_trade"})
    proven_actions: frozenset[str] = frozenset({"settlement", "large_trade", "state_commit"})

    def allows(self, action: str, finality: Finality) -> bool:
        if action in self.proven_actions:
            return finality in {Finality.PROVEN, Finality.SETTLED}
        if action in self.attested_actions:
            return finality in {Finality.ATTESTED, Finality.PROVEN, Finality.SETTLED}
        return False


class PoseidonRTMRHardware(Protocol):
    """Future silicon contract: dual SHA-384 + Poseidon2 native extend."""

    def extend_sha384_poseidon2(self, sha384_state: bytes, poseidon_state: bytes, event: bytes) -> tuple[bytes, bytes]: ...


class HardwareMemoryRoot(Protocol):
    """Future silicon contract: CPU-derived integrity/algebraic root of TD memory."""

    def memory_root(self) -> bytes: ...


class VerifiableMatmulVerifier(Protocol):
    """Line-rate verifier hook for GKR/sumcheck/Freivalds-style inference checks."""

    def verify(self, commitment: str, proof: dict[str, Any], challenge_seed: bytes) -> bool: ...


class ReplayBeacon(Protocol):
    """External randomness source; beacon output must be unpredictable at commitment time."""

    def latest(self) -> tuple[str, bytes]: ...


class DeterministicVerifier:
    """Reference verifier for CI: proves the challenge transcript is internally bound."""

    def verify(self, proof: dict[str, Any], challenge: Challenge) -> bool:
        return (
            proof.get("commitment") == challenge.commitment
            and tuple(proof.get("indices", ())) == challenge.indices
            and proof.get("proof_digest") == h({
                "commitment": challenge.commitment,
                "indices": challenge.indices,
                "payloads": proof.get("payloads", []),
            })
        )


def make_report_data(execution_id: str, commitment: SegmentCommitment) -> str:
    return h({
        "schema": "uqos.refereed.report-data.v1",
        "execution_id": execution_id,
        "segment_root": commitment.root,
        "segment_count": commitment.segment_count,
    })


def build_segments(items: Sequence[dict[str, Any]]) -> list[Segment]:
    return [Segment(i, h({"index": i, "item": item}), dict(item)) for i, item in enumerate(items)]


def make_reference_proof(execution: RefereedExecution) -> dict[str, Any]:
    if execution.challenge is None:
        raise RuntimeError("challenge required")
    payloads = [execution.segments[i].payload for i in execution.challenge.indices]
    return {
        "commitment": execution.challenge.commitment,
        "indices": list(execution.challenge.indices),
        "payloads": payloads,
        "proof_digest": h({
            "commitment": execution.challenge.commitment,
            "indices": execution.challenge.indices,
            "payloads": payloads,
        }),
    }
