"""UQOS Substrate: state synchronization, SIG-TD evidence and metering."""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import dataclass
from typing import Any, Callable

from receiptchain_v3 import ReceiptChain
from uqos_stream import StateEvent, StateLedger


@dataclass(frozen=True)
class UsageRecord:
    event_id: str
    meter: str
    units: int
    state_hash: str
    idempotency_key: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "meter": self.meter,
            "units": self.units,
            "state_hash": self.state_hash,
            "idempotency_key": self.idempotency_key,
        }


class UsageMeter:
    """Deterministic metering boundary; billing providers consume these records."""

    def __init__(self) -> None:
        self.records: list[UsageRecord] = []
        self._seen: set[str] = set()

    def charge(self, event_id: str, meter: str, units: int, state_hash: str, idempotency_key: str) -> UsageRecord | None:
        if idempotency_key in self._seen:
            return None
        record = UsageRecord(event_id, meter, max(1, int(units)), state_hash, idempotency_key)
        self.records.append(record)
        self._seen.add(idempotency_key)
        return record

    def charge_event(self, event: StateEvent, meter: str = "stream_event") -> UsageRecord | None:
        payload_bytes = len(json.dumps(event.payload, separators=(",", ":")).encode("utf-8"))
        return self.charge(event.event_id, meter, payload_bytes, event.state_hash, event.idempotency_key)

    def export_jsonl(self) -> str:
        return "".join(json.dumps(r.as_dict(), sort_keys=True) + "\n" for r in self.records)


class UQOSSubstrate:
    """Single composition point for live state, ReceiptChain, SIG-TD and billing meters."""

    def __init__(self, state_db: str = ".uqos/state.json", receipt_db: str = ".uqos/receipts.sqlite3"):
        self.state_path = state_db
        self.receipt_chain = ReceiptChain(receipt_db)
        self.ledger = StateLedger({})
        self.usage = UsageMeter()
        self._persist()

    def _persist(self) -> None:
        os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({
                "state": self.ledger.state,
                "state_version": self.ledger.state_version,
                "state_hash": self.ledger.state_hash,
                "event_count": len(self.ledger.events),
            }, fh, sort_keys=True, separators=(",", ":"))
        os.replace(tmp, self.state_path)

    async def apply(self, **kwargs: Any) -> StateEvent:
        event = await self.ledger.apply(**kwargs)
        self.usage.charge_event(event)
        self._persist()
        return event

    def receipt_step(self, run_id: str, owner: str, fence: int, event: StateEvent) -> str:
        return self.receipt_chain.record_step(
            run_id, owner, fence,
            {"schema": "uqos.stream.step.v1", "event": event.as_dict()},
        )

    def record_ttc_evidence(self, evidence: dict[str, Any], *, state_hash: str | None = None) -> UsageRecord:
        evidence_hash = evidence.get("evidence_hash") or hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return self.usage.charge(
            evidence_hash,
            "verified_candidate" if evidence.get("accepted") else "ttc_routed_event",
            1,
            state_hash or self.ledger.state_hash,
            f"sigtd:{evidence_hash}",
        )

    def record_smt_time(self, elapsed_us: float, *, state_hash: str | None = None) -> UsageRecord:
        units = max(1, math.ceil(float(elapsed_us) / 1000.0))
        event_id = hashlib.sha256(f"smt:{elapsed_us}:{state_hash or self.ledger.state_hash}".encode()).hexdigest()
        return self.usage.charge(
            event_id,
            "smt_verification_ms",
            units,
            state_hash or self.ledger.state_hash,
            event_id,
        )

    def attestation_binding(self, run_id: str, owner: str, fence: int) -> dict[str, Any]:
        return self.receipt_chain.attestation_binding(run_id, owner, fence)

    def close_with_attestation(
        self,
        run_id: str,
        owner: str,
        fence: int,
        attestation_factory: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        binding = self.attestation_binding(run_id, owner, fence)
        attestation = attestation_factory(binding)
        return self.receipt_chain.close_run(run_id, owner, fence, attestation)

    def pricing_meter_export(self) -> dict[str, Any]:
        return {
            "schema": "uqos.billing.meter.v2",
            "meters": {
                "stream_event": sum(1 for r in self.usage.records if r.meter == "stream_event"),
                "stream_bytes": sum(r.units for r in self.usage.records if r.meter == "stream_event"),
                "ttc_routed_event": sum(r.units for r in self.usage.records if r.meter == "ttc_routed_event"),
                "smt_verification_ms": sum(r.units for r in self.usage.records if r.meter == "smt_verification_ms"),
                "verified_candidate": sum(r.units for r in self.usage.records if r.meter == "verified_candidate"),
                "verified_receipt": 0,
            },
            "usage_sha256": hashlib.sha256(self.usage.export_jsonl().encode()).hexdigest(),
        }


def development_attestation(binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": "development",
        "binding": binding,
        "quote": "UNVERIFIED_DEVELOPMENT_PLACEHOLDER",
        "collateral": "UNVERIFIED_DEVELOPMENT_PLACEHOLDER",
    }
