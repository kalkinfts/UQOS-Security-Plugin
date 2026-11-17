from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from uqos_audit import append_audit
from uqos_env import Backend, detect_backend, environment_snapshot
from uqos_safeguards import authorize

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
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
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

    readers = [
        asyncio.create_task(pump("stdout", process.stdout)),
        asyncio.create_task(pump("stderr", process.stderr)),
    ]
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
            print(json.dumps({
                "schema": "uqos.security.event.v1",
                "event": "execution_started",
                "timestamp_ns": time.time_ns(),
                "tool": args.tool,
                "backend": backend.name,
            }), flush=True)
            def emit_event(event: dict[str, Any]) -> None:
                print(json.dumps({"schema": "uqos.security.event.v1", **event}), flush=True)

            events, returncode = await stream_command(command, timeout, on_event=emit_event)
            base.update({
                "status": "timeout" if returncode == 124 else "completed",
                "returncode": returncode,
                "output_events": len(events),
                "stdout": "".join(e["data"] for e in events if e["stream"] == "stdout"),
                "stderr": "".join(e["data"] for e in events if e["stream"] == "stderr"),
                "duration_ms": round((time.time_ns() - started) / 1_000_000, 3),
            })

        proof = attest_result(base)
        base["attestation"] = proof
        base["result_sha256"] = proof["digest"] if proof["algorithm"] == "sha256" else None
        audit_hash = append_audit(args.audit_file, {
            "tool": args.tool,
            "target": args.target,
            "status": base["status"],
            "attestation": proof,
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
        try:
            error["audit_record_hash"] = append_audit(args.audit_file, {
                "tool": args.tool, "target": args.target, "status": "blocked",
                "error_type": type(exc).__name__,
            })
        except Exception:
            pass
        print(json.dumps(error, indent=2, sort_keys=True), flush=True)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="UQOS authorized security runner with async JSONL streaming")
    parser.add_argument("--tool", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--execute", action="store_true", help="Run an active check; dry-run is the default")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--audit-file", default=".uqos/audit.jsonl")
    return asyncio.run(async_main(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
