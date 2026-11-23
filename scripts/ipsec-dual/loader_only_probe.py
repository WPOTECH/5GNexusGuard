#!/usr/bin/env python3
"""loader_only_probe.py — Minimal BPF loader using libbpf with probe-only mode.

Compiles and loads BPF programs for health-control validation without
full enforcement. Used during KVM acceptance testing.
"""

import subprocess
import sys
from pathlib import Path


def compile_bpf(source):
    """Compile a BPF source file with minimal includes."""
    source_path = Path(source)
    out_path = source_path.parent / (source_path.stem + ".o")

    cmd = [
        "clang", "-target", "bpf",
        "-I/usr/include/x86_64-linux-gnu",
        "-I" + str(str(source_path).rsplit('/', 1)[0]),
        "-c", str(source_path),
        "-o", str(out_path),
    ]

    print(f"loader compile: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: BPF compile failed:\n{result.stderr}", file=sys.stderr)
        return None
    return out_path


def main():
    parser = __import__('argparse').ArgumentParser(
        description="loader_only_probe: compile BPF in probe-only mode")
    parser.add_argument('source', help='BPF source file (.bpf.c)')
    args = parser.parse_args()

    out = compile_bpf(args.source)
    if out is None:
        sys.exit(1)
    print(f"loader_only_probe complete: {out}")


if __name__ == "__main__":
    main()