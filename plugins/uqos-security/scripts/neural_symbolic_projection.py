"""Neural-symbolic projection-head contract.

The model emits normal vocabulary logits plus a bounded SMT-LIB2 delta.
This module validates the delta envelope and canonicalizes it before the
native Rust verifier receives it. Training is intentionally a separate model
artifact; this is the production inference boundary.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class ProjectionOutput:
    token_id: int
    logit_prob: float
    smtlib2_delta: str
    kv_cache_hash: str

    def canonical(self) -> bytes:
        return json.dumps(
            {
                "token_id": self.token_id,
                "logit_prob": self.logit_prob,
                "smtlib2_delta": self.smtlib2_delta,
                "kv_cache_hash": self.kv_cache_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def commitment(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()


class SMTDeltaPolicy:
    """Fail-closed envelope for model-emitted symbolic deltas."""

    ALLOWED_FORMS: Sequence[str] = (
        "(assert ",
        "(set-logic ",
    )

    def __init__(self, max_bytes: int = 4096):
        self.max_bytes = max_bytes

    def validate(self, delta: str) -> None:
        raw = delta.encode()
        if len(raw) > self.max_bytes:
            raise ValueError("SMT delta exceeds bounded projection envelope")
        if "\x00" in delta:
            raise ValueError("NUL byte rejected")
        stripped = delta.strip()
        if stripped and not all(
            line.lstrip().startswith(self.ALLOWED_FORMS)
            for line in stripped.splitlines()
        ):
            raise ValueError("SMT delta contains an unapproved top-level form")


def project(
    token_id: int,
    logit_prob: float,
    smtlib2_delta: str,
    kv_cache_hash: str,
    *,
    policy: SMTDeltaPolicy | None = None,
) -> ProjectionOutput:
    p = policy or SMTDeltaPolicy()
    p.validate(smtlib2_delta)
    if not 0.0 <= logit_prob <= 1.0:
        raise ValueError("logit_prob must be within [0,1]")
    if len(kv_cache_hash) != 64:
        raise ValueError("kv_cache_hash must be a SHA-256 commitment")
    return ProjectionOutput(token_id, logit_prob, smtlib2_delta, kv_cache_hash)
