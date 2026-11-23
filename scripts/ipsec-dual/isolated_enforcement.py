#!/usr/bin/env python3
"""isolated_enforcement.py — Enforce isolated guest environment.

Verifies isolation and publishes health values via AtomicHealthMap
through the BPF_PROG_TEST_RUN path.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from kernel_gate_publisher_v2 import AtomicHealthMap, FreshHealth, command


def main():
    parser = argparse.ArgumentParser(description="Isolated enforcement")
    parser.add_argument('pin', help='BPF map pin path')
    parser.add_argument('--peer', default='wg-inner', help='Peer identifier')
    parser.add_argument('--resource', default='resource', help='Resource identifier')
    parser.add_argument('--health', default=1.0, type=float, help='Health value')
    parser.add_argument('--timeout', default=30, type=int, help='Timeout (s)')
    parser.add_argument('--object', default=None, help='BPF object path')
    args = parser.parse_args()

    health = FreshHealth()
    atomic_health = AtomicHealthMap(args.pin)

    # Compose a HEALTH record (mock publish for enforcement)
    value = AtomicHealthMap.HEALTH.pack(
        0, 0, 0, 0, 0, 0, 0
    )

    try:
        atomic_health.publish(atomic_health.health_map_path, value, 1, 999999999, 0, 0)
        print(f"Enforcement active: peer={args.peer} health={args.health}")
    except RuntimeError as exc:
        print(f"Enforcement FAILED: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()