from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from uqos_audit import append_audit
from uqos_env import Backend, detect_backend, environment_snapshot
from uqos_safeguards import authorize
from uqos_substrate import UQOSSubstrate, development_attestation

MAX_TIMEOUT = 300
DEFAULT_TIMEOUT = 60


def build_command(tool: str, target: str, prefix: tuple[str, ...]) -> list[str]:
    if tool == "nmap":
        return [*prefix, "-Pn", target]
    if tool == "httpx":
        return [*prefix, "-silent", "-u", target]
    if tool == "nuclei":
        return [*prefix, "-u", target]
    if tool == "nikto":
        return [*prefix, "-h", target]
    if tool == "amass":
        return [*prefix, "enum", "-d", target]
    if tool == "subfinder":
        return [*prefix, "-d", target]
    raise ValueError(f"No command adapter is registered for: {tool}")


async def stream_command(command: list[str], timeout: float, on_event=None) -> tuple[list[dict[str, Any]], int]:
    """Run a bounded child process; invoke on_event immediately for each output chunk."""
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
    events: list[dict[str, Any]] = []
    sequence = 0

    async def pump(stream_name: str, stream: asyncio.StreamReader) -> None:
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                break
            await queue.put({
                "event": "output",
                "stream": stream_name,
                "data": chunk.decode("utf-8", errors="replace"),
                "timestamp_ns": time.time_ns(),
            })
        await queue.put(None)

    readers = [asyncio.create_task(pump("stdout", process.stdout)),
               asyncio.create_task(pump("stderr", process.stderr))]
    wait_task = asyncio.create_task(process.wait())
    completed_streams = 0
    timed_out = False
    deadline = asyncio.get_running_loop().time() + timeout

    while completed_streams < 2:
        try:
            if timed_out:
                item = await queue.get()
            else:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                item = await asyncio.wait_for(queue.get(), timeout=remaining)
        except asyncio.TimeoutError:
            timed_out = True
            if process.returncode is None:
                process.terminate()
            try:
                await asyncio.wait_for(asyncio.shield(wait_task), timeout=1.0)
            except asyncio.TimeoutError:
                process.kill()
                await wait_task
            continue
        if item is None:
            completed_streams += 1
        else:
            sequence += 1
            item["sequence"] = sequence
            events.append(item)
            if on_event is not None:
                on_event(item)

    await asyncio.gather(*readers, return_exceptions=True)
    return events, 124 if timed_out else int(process.returncode or 0)


def attest_result(result: dict[str, Any]) -> dict[str, str]:
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        import blake3  # type: ignore
        digest = blake3.blake3(canonical).hexdigest()
        algorithm = "blake3"
    except ImportError:
        digest = hashlib.sha256(canonical).hexdigest()
        algorithm = "sha256"
    return {"algorithm": algorithm, "digest": digest}


async def async_main(args: argparse.Namespace) -> int:
    started = time.time_ns()
    timeout = max(1, min(args.timeout, MAX_TIMEOUT))
    substrate = UQOSSubstrate(args.state_file, args.receipt_db)
    run_id = f"uqos-{uuid.uuid4()}"
    owner = args.receipt_owner
    fence: int | None = None

    try:
        authorization = authorize(args.tool, args.target, args.execute)
        try:
            backend = detect_backend(args.tool)
        except RuntimeError:
            if args.execute:
                raise
            backend = Backend("not-installed", (args.tool,))
        command = build_command(args.tool, args.target, backend.prefix)
        base: dict[str, Any] = {
            "schema": "uqos.security.result.v2",
            "timestamp_ns": started,
            "tool": args.tool,
            "target": args.target,
            "execution": authorization,
            "backend": backend.name,
            "command": command if args.execute else None,
            "environment": environment_snapshot(),
            "status": "dry-run" if not args.execute else "running",
        }

        if args.execute:
            fence = substrate.receipt_chain.begin_run(run_id, owner, ttl_ms=max(30_000, (timeout + 30) * 1000))
            started_event = await substrate.apply(
                topic="security-run",
                kind="EXECUTION_STARTED",
                payload={"run_id": run_id, "tool": args.tool, "target": args.target},
                idempotency_key=f"{run_id}:started",
            )
            substrate.receipt_step(run_id, owner, fence, started_event)
            print(json.dumps({
                "schema": "uqos.security.event.v1",
                "event": "execution_started",
                "timestamp_ns": time.time_ns(),
                "tool": args.tool,
                "backend": backend.name,
                "run_id": run_id,
                "state_hash": started_event.state_hash,
            }), flush=True)

            async def emit_event(event: dict[str, Any]) -> None:
                state_event = await substrate.apply(
                    topic="security-run",
                    kind="TOOL_OUTPUT",
                    payload=event,
                    idempotency_key=f"{run_id}:output:{event['sequence']}",
                )
                substrate.receipt_step(run_id, owner, fence, state_event)
                print(json.dumps({
                    "schema": "uqos.security.event.v1",
                    **event,
                    "run_id": run_id,
                    "state_version": state_event.state_version,
                    "state_hash": state_event.state_hash,
                    "previous_event_hash": state_event.previous_event_hash,
                }), flush=True)

            # stream_command is synchronous-callback based; bridge each event to the
            # substrate without blocking the child-process pump.
            pending: list[asyncio.Task] = []
            def on_event(event: dict[str, Any]) -> None:
                pending.append(asyncio.create_task(emit_event(event)))

            events, returncode = await stream_command(command, timeout, on_event=on_event)
            if pending:
                await asyncio.gather(*pending)
            base.update({
                "status": "timeout" if returncode == 124 else "completed",
                "returncode": returncode,
                "output_events": len(events),
                "stdout": "".join(e["data"] for e in events if e["stream"] == "stdout"),
                "stderr": "".join(e["data"] for e in events if e["stream"] == "stderr"),
                "duration_ms": round((time.time_ns() - started) / 1_000_000, 3),
            })
        else:
            base["state_hash"] = substrate.ledger.state_hash

        proof = attest_result(base)
        base["attestation"] = proof
        base["result_sha256"] = proof["digest"] if proof["algorithm"] == "sha256" else None

        if args.execute and fence is not None:
            result_event = await substrate.apply(
                topic="security-run",
                kind="EXECUTION_RESULT",
                payload={
                    "status": base["status"],
                    "returncode": base.get("returncode"),
                    "result_attestation": proof,
                },
                idempotency_key=f"{run_id}:result",
            )
            substrate.receipt_step(run_id, owner, fence, result_event)
            receipt = substrate.close_with_attestation(run_id, owner, fence, development_attestation)
            base["receipt"] = {
                "status": "development-receipt",
                "receipt_hash": receipt["receipt_hash"],
                "leaf_index": receipt["leaf_index"],
                "warning": "Not hardware-verified attestation; replace development_attestation with a trusted TDX verifier in production.",
            }
            base["state_hash"] = result_event.state_hash
            base["usage_meter"] = substrate.pricing_meter_export()

        audit_hash = append_audit(args.audit_file, {
            "tool": args.tool,
            "target": args.target,
            "status": base["status"],
            "attestation": proof,
            "run_id": run_id if args.execute else None,
            "state_hash": base.get("state_hash"),
        })
        base["audit_record_hash"] = audit_hash
        print(json.dumps({"schema": "uqos.security.result.v2", "event": "result", "result": base},
                         indent=2, sort_keys=True), flush=True)
        return 124 if base["status"] == "timeout" else 0

    except Exception as exc:
        error = {
            "schema": "uqos.security.result.v2",
            "timestamp_ns": started,
            "tool": args.tool,
            "target": args.target,
            "status": "blocked",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        if args.execute and fence is not None:
            try:
                error_event = await substrate.apply(
                    topic="security-run",
                    kind="EXECUTION_ERROR",
                    payload={"error_type": type(exc).__name__, "error": str(exc)},
                    idempotency_key=f"{run_id}:error",
                )
                substrate.receipt_step(run_id, owner, fence, error_event)
                receipt = substrate.close_with_attestation(run_id, owner, fence, development_attestation)
                error["receipt"] = {
                    "status": "development-receipt",
                    "receipt_hash": receipt["receipt_hash"],
                    "warning": "Not hardware-verified attestation.",
                }
            except Exception as receipt_exc:
                error["receipt_error"] = str(receipt_exc)
        try:
            error["audit_record_hash"] = append_audit(args.audit_file, {
                "tool": args.tool, "target": args.target, "status": "blocked",
                "error_type": type(exc).__name__, "run_id": run_id if args.execute else None,
            })
        except Exception:
            pass
        print(json.dumps(error, indent=2, sort_keys=True), flush=True)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="UQOS authorized security runner with stateful async JSONL streaming")
    parser.add_argument("--tool", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--execute", action="store_true", help="Run an active check; dry-run is the default")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--audit-file", default=".uqos/audit.jsonl")
    parser.add_argument("--state-file", default=".uqos/state.json")
    parser.add_argument("--receipt-db", default=".uqos/receipts.sqlite3")
    parser.add_argument("--receipt-owner", default="uqos-runner")
    return asyncio.run(async_main(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
