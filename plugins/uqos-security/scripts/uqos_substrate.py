"""UQOS Substrate: state synchronization + proof-carrying usage metering.

This module composes the event ledger with ReceiptChain without pretending that
software-generated evidence is hardware attestation. A production deployment
supplies a trusted attestation provider for receipt finalization.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Callable

from receiptchain_v3 import ReceiptChain, ReceiptError
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

    def charge_event(self, event: StateEvent, meter: str = "stream_event") -> UsageRecord | None:
        if event.idempotency_key in self._seen:
            return None
        units = max(1, len(json.dumps(event.payload, separators=(",", ":")).encode("utf-8")))
        record = UsageRecord(event.event_id, meter, units, event.state_hash, event.idempotency_key)
        self.records.append(record)
        self._seen.add(event.idempotency_key)
        return record

    def export_jsonl(self) -> str:
        return "".join(json.dumps(r.as_dict(), sort_keys=True) + "\n" for r in self.records)


class UQOSSubstrate:
    """Single composition point for live state, event flow and ReceiptChain."""

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
            "schema": "uqos.billing.meter.v1",
            "meters": {
                "stream_event": len([r for r in self.usage.records if r.meter == "stream_event"]),
                "stream_bytes": sum(r.units for r in self.usage.records if r.meter == "stream_event"),
                "verified_receipt": 0,
            },
            "usage_sha256": hashlib.sha256(self.usage.export_jsonl().encode()).hexdigest(),
        }


def development_attestation(binding: dict[str, Any]) -> dict[str, Any]:
    """Development-only binding envelope; intentionally not TDX evidence."""
    return {
        "mode": "development",
        "binding": binding,
        "quote": "UNVERIFIED_DEVELOPMENT_PLACEHOLDER",
        "collateral": "UNVERIFIED_DEVELOPMENT_PLACEHOLDER",
    }
