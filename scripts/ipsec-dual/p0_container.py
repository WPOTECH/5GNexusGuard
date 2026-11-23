#!/usr/bin/env python3
"""p0_container.py — Run a BPF compilation container for p0 evidence.

Compiles kernel_gate_v2.bpf.c with proper include paths and produces
the .o artifact used by the guest acceptance test.
"""

import subprocess
import sys
from pathlib import Path


def compile_bpf(source_path, output_path=None, extra_includes=None):
    """Compile BPF source inside the p0 container context."""
    extra_includes = extra_includes or []
    source = Path(source_path)
    out = output_path or (source.parent / (source.stem + ".o"))

    cmd = [
        "clang", "-target", "bpf",
        "-I/usr/include/x86_64-linux-gnu",
        "-I" + str(source.parent),
        "-c", str(source),
        "-o", str(out),
    ]

    print(f"p0 compile: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: BPF compile failed:\n{result.stderr}", file=sys.stderr)
        return None
    print(f"  Output: {out}")
    return out


def main():
    parser = __import__('argparse').ArgumentParser(
        description="Compile BPF source for p0 container")
    parser.add_argument('source', help='BPF source file (.bpf.c)')
    parser.add_argument('-o', '--output', default=None, help='Output .o file')
    args = parser.parse_args()

    out = compile_bpf(args.source, args.output)
    if out is None:
        sys.exit(1)
    print(f"p0_container complete: {out}")


if __name__ == "__main__":
    main()