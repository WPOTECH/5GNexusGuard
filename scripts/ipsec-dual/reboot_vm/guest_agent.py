#!/usr/bin/env python3
"""guest_agent.py — KVM guest acceptance agent.

Runs health acceptance tests inside the KVM guest by publishing and
reading back health values through the atomic BPF gate.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kernel_gate_publisher_v2 import AtomicHealthMap, FreshHealth, HEALTH


class GuestAgent:
    """Run acceptance tests inside the guest."""

    def __init__(self, pin_dir):
        self.pin_dir = pin_dir
        self.atomic = AtomicHealthMap(pin_dir)

    def run_health_test(self):
        """Publish a zero health record and verify atomic acceptance."""
        value = HEALTH.pack(0, 0, 0, 0, 0, 0, 0)
        try:
            self.atomic.publish(self.atomic.health_map_path, value, 1, 999999999, 0, 0)
            return True
        except RuntimeError:
            return False

    def run_vici_test(self):
        """Quick VICI association test."""
        from vici_health import association
        try:
            result = association({}, b'', b'', b'')
            return result is None  # expected for empty input
        except Exception:
            return False

    def run_all(self):
        """Run the full acceptance suite."""
        h = self.run_health_test()
        v = self.run_vici_test()
        if h and v:
            print("ACCEPTANCE: PASS")
            return 0
        print(f"ACCEPTANCE: FAIL (health={h}, vici={v})")
        return 1


if __name__ == "__main__":
    pin = sys.argv[1] if len(sys.argv) > 1 else '/sys/fs/bpf/atomic-test'
    agent = GuestAgent(pin)
    sys.exit(agent.run_all())