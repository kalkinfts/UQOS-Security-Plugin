from __future__ import annotations
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path

SCRIPT_DIR=Path(__file__).resolve().parent
sys.path.insert(0,str(SCRIPT_DIR))
from uqos_audit import append_audit
from uqos_env import detect_backend,environment_snapshot
from uqos_safeguards import authorize

MAX_TIMEOUT=300
DEFAULT_TIMEOUT=60

def build_command(tool:str,target:str,prefix:tuple[str,...])->list[str]:
    if tool=="nmap": return [*prefix,"-Pn",target]
    if tool=="httpx": return [*prefix,"-silent","-u",target]
    if tool=="nuclei": return [*prefix,"-u",target]
    if tool=="nikto": return [*prefix,"-h",target]
    if tool in {"amass","subfinder"}: return [*prefix,"enum","-d",target]
    return [*prefix,target]

def main()->int:
    p=argparse.ArgumentParser(description="UQOS bounded security runner")
    p.add_argument("--tool",required=True); p.add_argument("--target",required=True)
    p.add_argument("--execute",action="store_true"); p.add_argument("--timeout",type=int,default=DEFAULT_TIMEOUT)
    p.add_argument("--audit-file",default=".uqos/audit.jsonl")
    a=p.parse_args(); timeout=max(1,min(a.timeout,MAX_TIMEOUT)); started=time.time_ns()
    try:
        auth=authorize(a.tool,a.target,a.execute); backend=detect_backend(a.tool)
        command=build_command(a.tool,a.target,backend.prefix)
        result={"schema":"uqos.security.result.v1","timestamp_ns":started,"tool":a.tool,"target":a.target,
                "execution":auth,"backend":backend.name,"command":command if a.execute else None,
                "environment":environment_snapshot(),"status":"dry-run" if not a.execute else "ready"}
        if a.execute:
            c=subprocess.run(command,capture_output=True,text=True,timeout=timeout,check=False)
            result.update({"status":"completed","returncode":c.returncode,"stdout":c.stdout,"stderr":c.stderr,
                           "duration_ms":round((time.time_ns()-started)/1000000,3)})
        canonical=json.dumps(result,sort_keys=True,separators=(",",":"))
        result["result_sha256"]=hashlib.sha256(canonical.encode()).hexdigest()
        result["audit_record_hash"]=append_audit(a.audit_file,{"tool":a.tool,"target":a.target,
            "status":result["status"],"result_sha256":result["result_sha256"]})
        print(json.dumps(result,indent=2,sort_keys=True)); return 0
    except subprocess.TimeoutExpired as exc:
        print(json.dumps({"schema":"uqos.security.result.v1","timestamp_ns":started,"tool":a.tool,
            "target":a.target,"status":"timeout","timeout_seconds":timeout,"stdout":exc.stdout or "",
            "stderr":exc.stderr or ""},indent=2)); return 124
    except Exception as exc:
        error={"schema":"uqos.security.result.v1","timestamp_ns":started,"tool":a.tool,"target":a.target,
               "status":"blocked","error_type":type(exc).__name__,"error":str(exc)}
        try:
            error["audit_record_hash"]=append_audit(a.audit_file,{"tool":a.tool,"target":a.target,
                "status":"blocked","error":str(exc)})
        except Exception: pass
        print(json.dumps(error,indent=2)); return 2

if __name__=="__main__":
    raise SystemExit(main())
