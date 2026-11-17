from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class Backend:
    name: str
    prefix: tuple[str, ...]


def _available(command: list[str]) -> bool:
    try:
        check = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
        return check.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def detect_backend(tool: str) -> Backend:
    """Choose only a backend whose executable or explicitly configured image exists."""
    native = shutil.which(tool)
    if native:
        return Backend("native", (native,))

    if platform.system() == "Windows" and shutil.which("wsl"):
        if _available(["wsl", "which", tool]):
            return Backend("wsl", ("wsl", tool))

    image = os.environ.get(f"UQOS_IMAGE_{tool.upper()}")
    if image and shutil.which("docker") and _available(["docker", "image", "inspect", image]):
        return Backend("docker", ("docker", "run", "--rm", image, tool))
    if image and shutil.which("podman") and _available(["podman", "image", "inspect", image]):
        return Backend("podman", ("podman", "run", "--rm", image, tool))

    raise RuntimeError(
        f"No verified backend for {tool}. Install it natively, make it available in WSL, "
        f"or set UQOS_IMAGE_{tool.upper()} to a locally available container image."
    )


def environment_snapshot() -> dict[str, str]:
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "python": platform.python_version(),
        "cwd": os.getcwd(),
    }
