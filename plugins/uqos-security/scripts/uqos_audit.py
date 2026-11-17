from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


def append_audit(path: str, event: dict) -> str:
    """Append a SHA-256 chained audit record and return its record hash."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    previous = ""
    if destination.exists():
        lines = [line for line in destination.read_text(encoding="utf-8").splitlines() if line]
        if lines:
            previous = json.loads(lines[-1]).get("record_hash", "")
    record = {
        "timestamp_ns": time.time_ns(),
        "previous_hash": previous,
        "event": event,
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    record["record_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return record["record_hash"]
