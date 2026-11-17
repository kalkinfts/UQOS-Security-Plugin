from __future__ import annotations
import os, platform, shutil
from dataclasses import dataclass

@dataclass(frozen=True)
class Backend:
    name: str
    prefix: tuple[str, ...]

def detect_backend(tool: str) -> Backend:
    if shutil.which(tool):
        return Backend("native", (tool,))
    if platform.system() == "Windows" and shutil.which("wsl"):
        return Backend("wsl", ("wsl", tool))
    if shutil.which("docker"):
        return Backend("docker", ("docker","run","--rm",f"uqos/{tool}:latest",tool))
    if shutil.which("podman"):
        return Backend("podman", ("podman","run","--rm",f"uqos/{tool}:latest",tool))
    raise RuntimeError(f"No execution backend available for tool: {tool}")

def environment_snapshot() -> dict[str,str]:
    return {"os":platform.system(),"os_release":platform.release(),"python":platform.python_version(),"cwd":os.getcwd()}
