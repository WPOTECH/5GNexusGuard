#!/usr/bin/env python3
"""Scapy burst sender for TC filter testing."""
from scapy.all import *
import time

# Discover and configure interface
for _if in ["veth_tc", "eth0"]:
    try:
        _ = open(f"/sys/class/net/{_if}/").read()
        conf.iface = _if
        conf.ifaces = {_if: open(f"/sys/class/net/{_if}/address").read().strip()}
        break
    except:
        pass

# Send 5 packets quickly
for i in range(5):
    raw_data = b"ping" + bytes([i])
    pkt = IP(src="10.30.30.11", dst="10.30.30.10")/UDP(sport=55555+i, dport=51820)/raw_data
    send(pkt, verbose=0)
    time.sleep(0.05)

print("BURST_SENT:5")