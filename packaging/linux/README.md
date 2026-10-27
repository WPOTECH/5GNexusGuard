# P2 Linux operational packaging — first milestone

This milestone builds the real Quarkus application into a local Debian package.
It does not rebuild a frontend, modify the checkout's `target/`, install test
credentials, or start a service during installation. STANDARD remains default.
The packaged service runs as `defenderlink`, with systemd-scoped NET_ADMIN and
private durable state; it never adds file capabilities to a shared Java binary.

```sh
# Ordinary user; cached Maven dependencies required, output must be new.
bash packaging/build-deb.sh /absolute/new-scratch-directory
# Review SHA256SUMS and package hooks before explicitly approved installation.
sudo bash install.sh --package /absolute/defenderlink-mesh_VERSION_ARCH.deb
# The default install is offline. --install-deps explicitly permits apt fetching.
sudoedit /etc/defenderlink/node.json
5gnexus validate
5gnexus diagnostics
sudo 5gnexus start
5gnexus status
5gnexus connect SERVICE_ID
5gnexus disconnect SERVICE_ID
sudo 5gnexus stop
```

The default HTTP bind is loopback. Set an explicit management address and
WireGuard endpoint for the intended trusted prototype network. Existing
management/discovery APIs are not promoted to a production authentication
boundary by packaging them. No installer discovers an address or opens host
firewall rules automatically. `deploy.sh` delegates only to this explicit local
installer; it no longer pulls main, removes installations, or SSHs to a fixed
machine. Existing incompatible state ownership is rejected by `preinst` before
unpacking; migration requires an explicit operator action. Removal retains
identities, ledger data and WireGuard configuration.

Persistent paths:

- `/etc/defenderlink/node.json`: validated operator configuration, no keys.
- `/var/lib/defenderlink`: private service identity and ledger state.
- `/etc/wireguard/defenderlink`: private config location compatible with the
  existing `/usr/bin/wg` AppArmor confinement.
- `/opt/defenderlink`: package-owned application and launcher.

The current package is a STANDARD runtime foundation. `DUAL_TUNNEL` is recognized
but startup is explicitly refused until service integration of the actual V2
Java exporter, AA, supervisor, tunnel health and BPF gate is qualified. The
isolated fixture is never called by the product launcher, and no synthetic
credentials are supplied. No production admission option can be enabled.

Prepared validation commands need fresh operator approval before execution:

```sh
python3 scripts/operational/run_standard.py --parent-approved \
  --jar /absolute/built-product-runner.jar --evidence /absolute/new-private-evidence
python3 scripts/ipsec-dual/reboot_vm/export_retest.py run --parent-approved \
  --directory /tmp/mesh-p2-export-vm-01
```

The STANDARD check runs two real application JVMs with separate private data and
network namespaces in the reviewed Docker image, real gossip/registration,
ledger service authorization, real `/usr/bin/wg`, protected TCP, distinct-service
interface checks and disconnect cleanup. It has not yet run. The export test
boots only a private copy of the stopped P1 disposable disk, requests status and
export, verifies retained artifact hashes and shuts down its own VM. It does
not rerun P1 authorization/packet cases or modify the original evidence.

Host snapshot equality is recorded independently from export success; external
Docker churn must not be concealed. The original P1 runner result remains FAIL,
and its independently reviewed reboot packet result remains scoped PASS.

Read-only pfSense inspection found the persistent domain shut off, one virtio
interface on libvirt `default`, one persistent disk, and no snapshots. It was
not powered on or altered. A separately approved safe pfSense target is still
required for real interoperability.

Validated so far: offline package build and extraction, dependency/configuration
diagnostics, package/unit syntax and systemd verification, 292 Python security
regressions (14 skipped), five deployment negative controls, and 33 Java tests.
Privileged installation, real service lifecycle, STANDARD packets, native
service integration, performance comparison and recovery qualification remain
outstanding. This milestone does not mark P2 working or P1 production-accepted.

STANDARD lifecycle corrections also have four focused Java regressions: full
scope interface naming, refusal to delete an existing name, kernel index/alias
ownership checks, and retained failed-teardown tracking. These have not yet
received packet sign-off. Ownership records remain process-local; crash
reconciliation and partial-creation recovery are outstanding operational gates.
