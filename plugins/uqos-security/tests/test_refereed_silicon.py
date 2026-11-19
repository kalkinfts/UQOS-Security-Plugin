import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from refereed_silicon import (
    DeterministicVerifier, ExecutionPolicy, Finality, HeterogeneousQuorum,
    RefereedExecution, AttestationResult, build_segments, detection_probability,
    make_reference_proof, make_report_data, derive_challenge,
)


def test_challenge_is_deterministic_and_bound():
    beacon = b"public-beacon-2026"
    c = "11" * 32
    assert derive_challenge(beacon, c, 100, 7) == derive_challenge(beacon, c, 100, 7)


def test_detection_probability():
    assert detection_probability(0.5, 0) == 0.0
    assert detection_probability(0.5, 10) > 0.99


def test_attested_then_proven_then_settled():
    segments = build_segments([{"x": i} for i in range(20)])
    commitment_root = __import__("hashlib").sha256(
        __import__("json").dumps(
            {"schema": "uqos.segment.commitment.v1", "segments": [s.digest for s in segments]},
            sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    from refereed_silicon import SegmentCommitment
    commitment = SegmentCommitment(commitment_root, len(segments), tuple(s.digest for s in segments))
    execution_id = "exec-1"
    report_data = make_report_data(execution_id, commitment)
    q = HeterogeneousQuorum(frozenset({"tdx", "sev-snp", "arm-cca"}), threshold=2)
    ex = RefereedExecution(
        execution_id, segments,
        [
            AttestationResult("tdx", True, "tdx-1"),
            AttestationResult("sev-snp", True, "sev-1"),
        ],
        q, report_data,
    )
    ex.commit_segments()
    assert ex.establish_attested_frontier()
    assert ex.finality == Finality.ATTESTED

    ex.open_challenge("beacon-1", b"unpredictable", 4)
    proof = make_reference_proof(ex)
    assert ex.verify_spot_check(proof, DeterministicVerifier())
    assert ex.finality == Finality.PROVEN
    assert ex.settle()
    assert ex.finality == Finality.SETTLED


def test_quorum_rejects_single_vendor():
    q = HeterogeneousQuorum(frozenset({"tdx", "sev-snp", "arm-cca"}), threshold=2)
    assert not q.accept([AttestationResult("tdx", True, "x")])
