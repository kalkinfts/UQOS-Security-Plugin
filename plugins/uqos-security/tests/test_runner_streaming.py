import asyncio
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from uqos_run import stream_command, attest_result


def test_attestation_identifies_real_hash_algorithm():
    result = {"schema": "uqos.security.result.v2", "status": "completed"}
    proof = attest_result(result)
    assert proof["algorithm"] in {"blake3", "sha256"}
    assert len(proof["digest"]) == (64 if proof["algorithm"] == "sha256" else 64)


def test_stream_command_emits_stdout_and_stderr_events():
    async def run():
        events, returncode = await stream_command(
            [sys.executable, "-c", "import sys; print('hello'); print('warning', file=sys.stderr)"],
            timeout=5,
        )
        assert returncode == 0
        assert any(e["stream"] == "stdout" and "hello" in e["data"] for e in events)
        assert any(e["stream"] == "stderr" and "warning" in e["data"] for e in events)
    asyncio.run(run())


def test_stream_command_times_out_and_stops_child():
    async def run():
        events, returncode = await stream_command(
            [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(5)"],
            timeout=1.0,
        )
        assert returncode == 124
        assert any("started" in e["data"] for e in events)
    asyncio.run(run())

from uqos_audit import append_audit


def test_audit_records_form_a_hash_chain(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    first = append_audit(str(audit_path), {"status": "first"})
    second = append_audit(str(audit_path), {"status": "second"})
    records = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert records[0]["record_hash"] == first
    assert records[1]["previous_hash"] == first
    assert records[1]["record_hash"] == second


def test_tool_adapters_use_valid_tool_specific_arguments():
    from uqos_run import build_command
    assert build_command("amass", "example.com", ("amass",)) == ["amass", "enum", "-d", "example.com"]
    assert build_command("subfinder", "example.com", ("subfinder",)) == ["subfinder", "-d", "example.com"]
