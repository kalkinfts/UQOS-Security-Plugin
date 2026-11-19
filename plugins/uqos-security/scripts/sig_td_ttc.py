"""UQOS SIG-TD: entropy-routed speculative symbolic execution."""

from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass
from typing import Any, Iterable, Protocol, Sequence

try:
    from z3 import And, Bool, Int, Not, Or, Solver, unknown, unsat
except ImportError:  # pragma: no cover
    And = Bool = Int = Not = Or = Solver = None
    unknown = unsat = None


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def shannon_entropy(logits: Sequence[float]) -> float:
    if not logits:
        return 0.0
    m = max(float(x) for x in logits)
    exps = [math.exp(float(x) - m) for x in logits]
    total = sum(exps)
    return -sum((x / total) * math.log2((x / total) + 1e-12) for x in exps)


def estimate_fvc(ast_fragment: str, *, solver_history: float = 0.0) -> float:
    """Cheap normalized heuristic; production replaces this with calibrated ML FVC."""
    text = ast_fragment or ""
    branch = text.count("if ") + text.count("else") + text.count("match") + text.count("switch")
    memory = text.count("*") + text.count("[") + text.count("lock") + text.count("atomic")
    concurrency = text.count("thread") + text.count("async") + text.count("await")
    raw = 0.12 * min(branch, 8) + 0.12 * min(memory, 8) + 0.18 * min(concurrency, 4) + 0.25 * max(0.0, solver_history)
    return min(1.0, raw)


class EGraphReducer(Protocol):
    def reduce(self, ast_fragment: str) -> str: ...


@dataclass(frozen=True)
class RoutingPlan:
    mode: str
    entropy_bits: float
    speculative_k: int
    smt_budget_ms: float
    fvc_score: float


@dataclass(frozen=True)
class SpeculativeNode:
    token_id: int
    ast_fragment: str
    logit_prob: float
    smt_constraints: tuple[Any, ...]
    kv_cache_hash: str
    fvc_score: float = 0.0


@dataclass(frozen=True)
class VerificationResult:
    accepted: bool
    token_id: int | None
    status: str
    elapsed_us: float
    checked_candidates: int
    reason: str
    evidence_hash: str


class ApexTTCRouter:
    def __init__(self, entropy_threshold: float = 1.45, fvc_threshold: float = 0.65):
        self.entropy_threshold = entropy_threshold
        self.fvc_threshold = fvc_threshold

    def compute_routing_budget(
        self,
        logits: Sequence[float],
        *,
        in_critical_section: bool,
        fvc_score: float = 0.0,
    ) -> RoutingPlan:
        entropy = shannon_entropy(logits)
        trigger = entropy > self.entropy_threshold or fvc_score >= self.fvc_threshold or in_critical_section
        if not trigger:
            return RoutingPlan("FAST_NEURAL_BYPASS", entropy, 1, 0.0, fvc_score)
        k = min(8, max(2, math.ceil((entropy + 1.0) * 1.5)))
        return RoutingPlan("APEX_SYMBOLIC_SPECULATION", entropy, k, 12.0, fvc_score)


class IncrementalSymbolicVerifier:
    def __init__(self, *, buffer_len: int = 1024):
        if Solver is None:
            raise RuntimeError("z3-solver is required for SIG-TD verification")
        self.solver = Solver()
        self.buffer_len = Int("buffer_len")
        self.write_idx = Int("write_idx")
        self.lock_held = Bool("lock_held")
        self.solver.add(self.buffer_len == buffer_len, self.write_idx >= 0)

    def verify(self, candidates: Sequence[SpeculativeNode], budget_ms: float) -> VerificationResult:
        start = time.perf_counter_ns()
        checked = 0
        for node in sorted(candidates, key=lambda x: x.logit_prob, reverse=True):
            if (time.perf_counter_ns() - start) / 1e6 >= budget_ms:
                break
            checked += 1
            self.solver.push()
            try:
                violation = Or(
                    self.write_idx >= self.buffer_len,
                    self.write_idx < 0,
                    Not(self.lock_held),
                )
                self.solver.add(And(*node.smt_constraints), violation)
                result = self.solver.check()
            finally:
                self.solver.pop()

            if result == unsat:
                elapsed_us = (time.perf_counter_ns() - start) / 1e3
                evidence = {
                    "schema": "uqos.sig-td.verification.v1",
                    "token_id": node.token_id,
                    "kv_cache_hash": node.kv_cache_hash,
                    "ast_hash": sha256_hex(node.ast_fragment),
                    "solver": "z3",
                    "result": "unsat_counterexample_search",
                    "checked_candidates": checked,
                }
                return VerificationResult(
                    True, node.token_id, "PROVEN_MODEL_SAFE", elapsed_us, checked,
                    "No modeled safety-counterexample exists under the asserted constraints.",
                    sha256_hex(evidence),
                )
            if result == unknown:
                continue

        elapsed_us = (time.perf_counter_ns() - start) / 1e3
        return VerificationResult(
            False, None, "REJECTED_OR_BUDGET_EXHAUSTED", elapsed_us, checked,
            "No candidate received an UNSAT counterexample result within the verification budget.",
            sha256_hex({
                "schema": "uqos.sig-td.verification.v1",
                "status": "rejected",
                "checked_candidates": checked,
            }),
        )


def build_candidate(token_id: int, ast_fragment: str, logit_prob: float,
                    constraints: Iterable[Any], kv_payload: Any, fvc_score: float = 0.0) -> SpeculativeNode:
    return SpeculativeNode(token_id, ast_fragment, logit_prob, tuple(constraints), sha256_hex(kv_payload), fvc_score)


def candidate_to_json(node: SpeculativeNode) -> dict[str, Any]:
    return {
        "token_id": node.token_id,
        "ast_fragment": node.ast_fragment,
        "logit_prob": node.logit_prob,
        "kv_cache_hash": node.kv_cache_hash,
        "fvc_score": node.fvc_score,
    }


__all__ = [
    "ApexTTCRouter", "EGraphReducer", "IncrementalSymbolicVerifier",
    "RoutingPlan", "SpeculativeNode", "VerificationResult",
    "build_candidate", "candidate_to_json", "estimate_fvc",
    "shannon_entropy", "sha256_hex",
]
