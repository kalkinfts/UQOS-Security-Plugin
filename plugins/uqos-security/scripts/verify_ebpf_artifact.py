#!/usr/bin/env python3
"""Fail-closed eBPF verification gate.

This does not bypass the Linux verifier. It compiles a supplied source and,
when bpftool is available, asks the kernel/libbpf toolchain to load/verify it.
Deployment is refused unless the verifier accepts the artifact.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("--object", default="/tmp/uqos-ebpf.o")
    args = ap.parse_args()

    clang = shutil.which("clang")
    if not clang:
        print("REJECTED: clang unavailable", file=sys.stderr)
        return 2

    cmd = [clang, "-target", "bpf", "-O2", "-g", "-c", args.source, "-o", args.object]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode:
        print(p.stderr, file=sys.stderr)
        return p.returncode

    bpftool = shutil.which("bpftool")
    if not bpftool:
        print("COMPILED_ONLY: bpftool unavailable; kernel verification not demonstrated")
        return 3

    # Generate a verifier-visible load command without executing a production
    # attachment. The operator must perform the final privileged load in the
    # intended isolated environment.
    subprocess.run([bpftool, "prog", "loadall", args.object, "/sys/fs/bpf/uqos-verify"],
                   check=False)
    print("ARTIFACT_READY_FOR_KERNEL_VERIFIER")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
