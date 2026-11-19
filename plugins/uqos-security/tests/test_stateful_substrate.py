import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from uqos_stream import StateLedger, BidirectionalStreamEngine, StreamError
from uqos_substrate import UQOSSubstrate, development_attestation


def test_state_hash_changes_and_stale_mutation_is_rejected():
    async def run():
        ledger = StateLedger({"x": 1})
        initial = ledger.state_hash
        await ledger.apply(
            topic="test", kind="SET", payload={"x": 2},
            mutation=lambda state, payload: payload,
            idempotency_key="x2",
        )
        assert ledger.state_hash != initial
        try:
            await ledger.apply(
                topic="test", kind="SET", payload={"x": 3},
                expected_state_hash=initial,
                mutation=lambda state, payload: payload,
                idempotency_key="x3",
            )
        except StreamError as exc:
            assert "STATE_DRIFT" in str(exc)
        else:
            raise AssertionError("stale mutation was accepted")
    asyncio.run(run())


def test_idempotency_replays_same_event():
    async def run():
        ledger = StateLedger({"x": 1})
        first = await ledger.apply(
            topic="test", kind="SET", payload={"x": 2},
            mutation=lambda state, payload: payload,
            idempotency_key="same",
        )
        second = await ledger.apply(
            topic="test", kind="SET", payload={"x": 999},
            mutation=lambda state, payload: payload,
            idempotency_key="same",
        )
        assert first.event_id == second.event_id
        assert ledger.state == {"x": 2}
        assert len(ledger.events) == 1
    asyncio.run(run())


def test_bidirectional_engine_round_trip():
    async def run():
        ledger = StateLedger({"messages": []})
        engine = BidirectionalStreamEngine(ledger)
        seen = []
        engine.subscribe(lambda event: seen.append(event))
        await engine.start()
        await engine.ingest({
            "topic": "chat", "kind": "MESSAGE",
            "payload": {"text": "hello"},
            "idempotency_key": "msg-1",
            "mutation": lambda state, payload: {
                **state,
                "messages": state.get("messages", []) + [payload],
            },
        })
        await asyncio.sleep(0)
        outbound = await engine.emit(
            topic="chat", kind="ACK", payload={"for": "msg-1"},
            expected_state_hash=ledger.state_hash,
            idempotency_key="ack-1",
        )
        await engine.stop()
        assert seen and seen[0].direction == "inbound"
        assert outbound.direction == "outbound"
        assert ledger.state_version == 2
    asyncio.run(run())


def test_receipted_substrate_emits_billing_meter_and_receipt(tmp_path):
    async def run():
        substrate = UQOSSubstrate(
            str(tmp_path / "state.json"),
            str(tmp_path / "receipts.sqlite3"),
        )
        fence = substrate.receipt_chain.begin_run("run-1", "test", ttl_ms=30_000)
        event = await substrate.apply(
            topic="security", kind="OUTPUT",
            payload={"stdout": "ok"},
            idempotency_key="run-1:1",
        )
        substrate.receipt_step("run-1", "test", fence, event)
        receipt = substrate.close_with_attestation(
            "run-1", "test", fence, development_attestation
        )
        assert receipt["receipt"]["schema"] == "receiptchain.receipt.v3"
        assert substrate.pricing_meter_export()["meters"]["stream_event"] == 1
    asyncio.run(run())
