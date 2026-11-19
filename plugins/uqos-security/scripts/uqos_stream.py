"""UQOS Stateful Bi-Directional Event-Driven Streaming substrate.

The substrate is transport-neutral: WebSockets/Supabase Broadcast/other transports
can feed events into the same deterministic state ledger. Every accepted mutation
gets a monotonic sequence, idempotency key, state hash and hash-chain predecessor.
Execution is optimistic-concurrency controlled: mutations carrying a stale expected
state hash are rejected before commit.

This is a synchronization/verification layer, not a claim that an LLM KV-cache is
directly mutable from outside the model runtime.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable


class StreamError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class StateEvent:
    event_id: str
    sequence: int
    direction: str
    topic: str
    kind: str
    emitted_ns: int
    payload: dict[str, Any]
    state_version: int
    state_hash: str
    previous_event_hash: str
    idempotency_key: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "sequence": self.sequence,
            "direction": self.direction,
            "topic": self.topic,
            "kind": self.kind,
            "emitted_ns": str(self.emitted_ns),
            "payload": self.payload,
            "state_version": self.state_version,
            "state_hash": self.state_hash,
            "previous_event_hash": self.previous_event_hash,
            "idempotency_key": self.idempotency_key,
        }


class StateLedger:
    """Deterministic in-memory state with replayable event/hash history."""

    def __init__(self, initial_state: dict[str, Any] | None = None):
        self.state: dict[str, Any] = json.loads(json.dumps(initial_state or {}, sort_keys=True))
        self.state_version = 0
        self.state_hash = sha256_json(self.state)
        self.previous_event_hash = sha256_json({"genesis": self.state_hash})
        self._seen: set[str] = set()
        self._events: list[StateEvent] = []
        self._lock = asyncio.Lock()

    @property
    def events(self) -> tuple[StateEvent, ...]:
        return tuple(self._events)

    async def apply(
        self,
        *,
        topic: str,
        kind: str,
        payload: dict[str, Any],
        direction: str = "inbound",
        expected_state_hash: str | None = None,
        idempotency_key: str | None = None,
        mutation: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]] | None = None,
    ) -> StateEvent:
        key = idempotency_key or str(uuid.uuid4())
        async with self._lock:
            if key in self._seen:
                for event in reversed(self._events):
                    if event.idempotency_key == key:
                        return event
            if expected_state_hash is not None and expected_state_hash != self.state_hash:
                raise StreamError(
                    f"STATE_DRIFT: expected={expected_state_hash} live={self.state_hash}"
                )
            next_state = (
                mutation(json.loads(json.dumps(self.state)), payload)
                if mutation is not None
                else json.loads(json.dumps(payload, sort_keys=True))
            )
            if not isinstance(next_state, dict):
                raise StreamError("Mutation must return a JSON object")
            self.state_version += 1
            self.state = next_state
            self.state_hash = sha256_json(self.state)
            sequence = len(self._events) + 1
            event_body = {
                "sequence": sequence,
                "direction": direction,
                "topic": topic,
                "kind": kind,
                "payload": payload,
                "state_version": self.state_version,
                "state_hash": self.state_hash,
                "previous_event_hash": self.previous_event_hash,
                "idempotency_key": key,
            }
            event_hash = sha256_json(event_body)
            event = StateEvent(
                event_id=str(uuid.uuid4()),
                sequence=sequence,
                direction=direction,
                topic=topic,
                kind=kind,
                emitted_ns=time.time_ns(),
                payload=payload,
                state_version=self.state_version,
                state_hash=self.state_hash,
                previous_event_hash=self.previous_event_hash,
                idempotency_key=key,
            )
            self._events.append(event)
            self._seen.add(key)
            self.previous_event_hash = event_hash
            return event


Handler = Callable[[StateEvent], Awaitable[None] | None]


class BidirectionalStreamEngine:
    """Persistent inbound/outbound queues around the UQOS state substrate."""

    def __init__(self, ledger: StateLedger, *, max_queue: int = 1024):
        self.ledger = ledger
        self.inbound: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=max_queue)
        self.outbound: asyncio.Queue[StateEvent] = asyncio.Queue(maxsize=max_queue)
        self._handlers: list[Handler] = []
        self._task: asyncio.Task | None = None

    def subscribe(self, handler: Handler) -> None:
        self._handlers.append(handler)

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._consume())

    async def stop(self) -> None:
        if self._task is not None:
            await self.inbound.put(None)
            await self._task
            self._task = None

    async def ingest(self, event: dict[str, Any]) -> None:
        await self.inbound.put(event)

    async def emit(
        self,
        *,
        topic: str,
        kind: str,
        payload: dict[str, Any],
        expected_state_hash: str | None = None,
        idempotency_key: str | None = None,
    ) -> StateEvent:
        event = await self.ledger.apply(
            topic=topic,
            kind=kind,
            payload=payload,
            direction="outbound",
            expected_state_hash=expected_state_hash,
            idempotency_key=idempotency_key,
        )
        await self.outbound.put(event)
        return event

    async def _consume(self) -> None:
        while True:
            item = await self.inbound.get()
            if item is None:
                return
            event = await self.ledger.apply(
                topic=str(item["topic"]),
                kind=str(item["kind"]),
                payload=dict(item.get("payload") or {}),
                direction="inbound",
                expected_state_hash=item.get("expected_state_hash"),
                idempotency_key=item.get("idempotency_key"),
                mutation=item.get("mutation"),
            )
            for handler in tuple(self._handlers):
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result

    async def snapshot(self) -> dict[str, Any]:
        async with self.ledger._lock:
            return {
                "state": json.loads(json.dumps(self.ledger.state, sort_keys=True)),
                "state_version": self.ledger.state_version,
                "state_hash": self.ledger.state_hash,
                "event_count": len(self.ledger.events),
                "previous_event_hash": self.ledger.previous_event_hash,
            }


async def run_demo() -> dict[str, Any]:
    ledger = StateLedger({"calendar_events": [{"id": "evt_1", "time": "14:00"}]})
    engine = BidirectionalStreamEngine(ledger)
    await engine.start()
    initial = ledger.state_hash

    await engine.ingest({
        "topic": "calendar",
        "kind": "EXTERNAL_MUTATION",
        "payload": {"add": {"id": "evt_2", "time": "15:00"}},
        "idempotency_key": "evt_2",
    })

    await asyncio.sleep(0)
    live = ledger.state_hash

    stale = None
    try:
        await engine.emit(
            topic="calendar",
            kind="BOOK",
            payload={"id": "evt_3", "time": "16:00"},
            expected_state_hash=initial,
        )
    except StreamError as exc:
        stale = str(exc)

    committed = await engine.emit(
        topic="calendar",
        kind="BOOK",
        payload={"id": "evt_3", "time": "16:00"},
        expected_state_hash=live,
        idempotency_key="book_evt_3",
    )
    await engine.stop()
    return {
        "initial_state_hash": initial,
        "live_state_hash": live,
        "stale_mutation": stale,
        "committed_state_hash": committed.state_hash,
        "event_count": len(ledger.events),
    }


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run_demo()), indent=2, sort_keys=True))
