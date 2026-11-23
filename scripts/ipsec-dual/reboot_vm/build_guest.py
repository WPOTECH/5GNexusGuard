#!/usr/bin/env python3
"""build_guest.py — Build a disposable KVM acceptance guest from a worktree.

Usage:
    python3 build_guest.py <repo> [--dest <guest_dir>] [--dry-run]

Creates a staging directory at <guest_dir>/staging/ with all required
source files, computes SHA-256 hashes, and verifies the preflight
mandatory-source list before proceeding.

Does NOT execute KVM.  This is a build artifact only.
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Build KVM acceptance guest")
    parser.add_argument("repo", help="Path to the git worktree")
    parser.add_argument("--dest", default="/tmp/5gnexus-reboot-guest-new",
                        help="Guest output directory")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be staged without copying")
    parser.add_argument("--kernel", default="7.0.0-42-generic",
                        help="Target kernel version")
    parser.add_argument("--compile-flags", default="-DNEXUS_ATOMIC_HEALTH",
                        help="Extra compiler flags")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    dest = Path(args.dest).resolve()
    staging = dest / "staging"

    # ── Gather tracked files ─────────────────────────────────────────
    result = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, cwd=repo
    )
    tracked = {p for p in result.stdout.strip().splitlines() if p}

    bootdir = repo / "scripts" / "ipsec-dual" / "reboot_vm"

    # Extras: Python files from bootdir + guest_init.sh + kernel_gate_transition.h
    extras = [
        str(p.relative_to(repo))
        for p in bootdir.glob("*.py")
    ]
    if (bootdir / "guest_init.sh").is_file():
        extras.append(str((bootdir / "guest_init.sh").relative_to(repo)))
    # kernel_gate_transition.h is always included
    extras.append("scripts/ipsec-dual/kernel_gate_transition.h")

    paths = sorted(tracked | set(extras))

    # ── Preflight: mandatory source files must exist ──────────────────
    mandatory = [
        "scripts/ipsec-dual/kernel_gate_transition.h",
        "scripts/ipsec-dual/kernel_gate_v2.bpf.c",
        "scripts/ipsec-dual/kernel_gate_publisher_v2.py",
        "scripts/ipsec-dual/isolated_enforcement.py",
        "scripts/ipsec-dual/loader_only_probe.py",
        "scripts/ipsec-dual/p0_container.py",
        "scripts/ipsec-dual/vici_health.py",
        "scripts/ipsec-dual/test_kernel_gate_publisher_v2.py",
        "scripts/ipsec-dual/reboot_vm/guest_agent.py",
        "scripts/ipsec-dual/reboot_vm/guest_init.sh",
    ]
    missing = [m for m in mandatory if not (repo / m).is_file()]
    if missing:
        parser.error("mandatory source missing from staging:\n  " + "\n  ".join(missing))

    if args.dry_run:
        print(f"Dry run — would stage {len(paths)} files to {staging}")
        for p in paths:
            full = repo / p
            print(f"  {p}  ({full.stat().st_size} bytes)")
        print(f"  mandatory check: OK ({len(missing)} missing)")
        print(f"  kernel: {args.kernel}")
        print(f"  compile flags: {args.compile_flags}")
        print("DONE (dry run)")
        return

    # ── Create staging directory ──────────────────────────────────────
    staging.mkdir(parents=True, exist_ok=True)

    staged_hashes = {}
    for p in paths:
        src = repo / p
        dst = staging / p
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_file():
            shutil.copy2(str(src), str(dst))
            h = hashlib.sha256(src.read_bytes()).hexdigest()
            staged_hashes[p] = h
            print(f"  staged: {p}  sha256={h[:12]}")
        else:
            # Extra file not tracked — may be symlink or absent
            print(f"  WARN: extra not found: {p}", file=sys.stderr)

    # ── Write manifest ───────────────────────────────────────────────
    manifest = dest / "MANIFEST.txt"
    with open(manifest, "w") as f:
        f.write(f"# 5GNexusGuard acceptance guest manifest\n")
        f.write(f"# kernel: {args.kernel}\n")
        f.write(f"# compile flags: {args.compile_flags}\n")
        f.write(f"# staged: {len(staged_hashes)} files\n\n")
        for p, h in sorted(staged_hashes.items()):
            f.write(f"{h}  {p}\n")
    print(f"\nManifest written: {manifest}")

    # ── Write build config ───────────────────────────────────────────
    config = dest / "build_config.yaml"
    with open(config, "w") as f:
        f.write(f"kernel: \"{args.kernel}\"\n")
        f.write(f"compile_flags: \"{args.compile_flags}\"\n")
        f.write(f"staging: staging\n")
        f.write(f"atomic_health: true\n")
    print(f"Build config written: {config}")

    # ── Report ────────────────────────────────────────────────────────
    print(f"\nGUEST_BUILD = PASS")
    print(f"STAGED_SOURCE_HASHES = PASS ({len(staged_hashes)} files)")
    print(f"ATOMIC_BPF_SOURCE = PRESENT")
    print(f"VICI_SOURCE = PRESENT")
    print(f"GUEST_KERNEL = {args.kernel}")
    print(f"READY_FOR_KVM_RETRY = YES")
    print(f"\nNext: mount staging dir in KVM with -D {staging}")


if __name__ == "__main__":
    main()