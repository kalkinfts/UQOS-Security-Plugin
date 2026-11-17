from __future__ import annotations
import hashlib,json,time
from pathlib import Path

def append_audit(path:str,event:dict)->str:
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); previous=""
    if p.exists():
        lines=[x for x in p.read_text(encoding="utf-8").splitlines() if x]
        if lines: previous=json.loads(lines[-1]).get("record_hash","")
    record={"timestamp_ns":time.time_ns(),"previous_hash":previous,"event":event}
    canonical=json.dumps(record,sort_keys=True,separators=(",",":"))
    record["record_hash"]=hashlib.sha256(canonical.encode()).hexdigest()
    with p.open("a",encoding="utf-8") as f: f.write(json.dumps(record,sort_keys=True)+"
")
    return record["record_hash"]
