import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from sig_td_ttc import (
    ApexTTCRouter,
    IncrementalSymbolicVerifier,
    build_candidate,
    candidate_to_json,
    shannon_entropy,
)


def test_entropy_router_bypasses_low_entropy():
    plan = ApexTTCRouter(entropy_threshold=1.0).compute_routing_budget(
        [12.0, -4.0, -5.0], in_critical_section=False
    )
    assert plan.mode == "FAST_NEURAL_BYPASS"
    assert plan.speculative_k == 1
    assert plan.smt_budget_ms == 0.0


def test_entropy_router_enters_symbolic_mode():
    plan = ApexTTCRouter(entropy_threshold=1.0).compute_routing_budget(
        [1.0, 0.9, 0.8], in_critical_section=False, fvc_score=0.9
    )
    assert plan.mode == "APEX_SYMBOLIC_SPECULATION"
    assert 2 <= plan.speculative_k <= 8
    assert plan.smt_budget_ms > 0


def test_incremental_verifier_rejects_bad_candidates_and_accepts_safe_one():
    try:
        from z3 import Int, Bool
    except ImportError:
        pytest.skip("z3-solver not installed")

    verifier = IncrementalSymbolicVerifier()
    x, lock = verifier.write_idx, verifier.lock_held

    candidates = [
        build_candidate(1, "ptr[idx + 1024] = val;", 0.42,
                        [lock == True, x == 1024], {"kv": "bad"}),
        build_candidate(2, "ptr[idx] = val; // unlocked", 0.36,
                        [lock == False, x == 512], {"kv": "unlock"}),
        build_candidate(3, "if (lock && idx < 1024) { ptr[idx] = val; }", 0.22,
                        [lock == True, x == 512], {"kv": "safe"}),
    ]
    result = verifier.verify(candidates, 100.0)
    assert result.accepted
    assert result.token_id == 3
    assert result.status == "PROVEN_MODEL_SAFE"
    assert result.checked_candidates == 3
    assert len(result.evidence_hash) == 64


def test_kv_cache_is_a_commitment_not_raw_cache_access():
    node = build_candidate(7, "return x + 1;", 0.5, [], {"layer": 1, "position": 7})
    encoded = candidate_to_json(node)
    assert len(encoded["kv_cache_hash"]) == 64
    assert "kv" not in encoded


def test_entropy_is_finite():
    assert shannon_entropy([0.0, 0.0]) > 0
