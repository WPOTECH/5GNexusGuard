"""TEST-ONLY authorization contract; no runtime BPF loader or AA integration.

A caller must verify fresh authority and liveness independently. This model does not
assert those facts, and must never be used to issue a production grant.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Authorization:
    boot: str
    epoch: str
    deadline_ns: int


@dataclass(frozen=True)
class Health:
    epoch: str
    deadline_ns: int


class Gate:
    def __init__(self, *, boot, peer, resource, port, health_window_ns=500_000_000):
        if not boot or not peer or not resource or not 0 < port < 65536:
            raise ValueError('exact scope required')
        if not 0 < health_window_ns <= 500_000_000:
            raise ValueError('health window must be at most 500ms')
        self.boot, self.peer, self.resource, self.port = boot, peer, resource, port
        self.health_window_ns = health_window_ns
        self.auth = None
        self.health = None
        self.attached = True  # Models an attached program; nft is a separate deny interlock.

    def admit(self, boot, epoch, deadline_ns, now_ns):
        if boot != self.boot or not epoch or now_ns < 0 or deadline_ns <= now_ns:
            raise ValueError('invalid or expired original BOOTTIME authority')
        if self.auth is not None and (epoch == self.auth.epoch or
                                      deadline_ns <= self.auth.deadline_ns):
            raise ValueError('replay or non-increasing authority')
        self.auth = Authorization(boot, epoch, deadline_ns)
        self.health = None  # Never carry a heartbeat across epochs.

    def heartbeat(self, boot, epoch, now_ns):
        if (self.auth is None or boot != self.boot or epoch != self.auth.epoch or
                now_ns < 0 or now_ns >= self.auth.deadline_ns or
                (self.health is not None and now_ns >= self.health.deadline_ns)):
            raise ValueError('stale/mismatched health; fresh admission required')
        self.health = Health(epoch, min(self.auth.deadline_ns,
                                       now_ns + self.health_window_ns))

    def permits(self, now_ns, peer, resource, port):
        return bool(self.attached and self.auth and self.health and
                    self.health.epoch == self.auth.epoch and
                    now_ns >= 0 and now_ns < self.auth.deadline_ns and
                    now_ns < self.health.deadline_ns and
                    (peer, resource, port) == (self.peer, self.resource, self.port))


def nft_interlock():
    """Separate nft base chain: install BEFORE TC, never replace production rules."""
    return '''table inet kernel_gate_v2_test {
 chain forward { type filter hook forward priority 10; policy drop;
  iifname "wg-inner" oifname "resource" ip saddr 10.79.0.1 ip daddr 10.80.0.2 tcp dport 8080 meta mark 0x5a17c0de accept
  iifname "resource" oifname "wg-inner" ip saddr 10.80.0.2 ip daddr 10.79.0.1 tcp sport 8080 meta mark 0x5a17c0de ct state established accept
 }
}'''
