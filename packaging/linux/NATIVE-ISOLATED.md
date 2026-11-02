# Installed Native Dual-Tunnel Access — isolated prototype

The optional `defenderlink-native-prototype` Debian add-on runs actual installed
services: live Java exporter → mTLS AA → native supervisor → TC/eBPF+nftables →
outer IKEv2/IPsec ESP with inner WireGuard → protected TCP resource. The fixed
prototype tuple is `10.79.0.1 → 10.80.0.2:8080`. This is not a generic production
deployment switch. STANDARD remains default, the normal DUAL_TUNNEL launcher
remains refused, and `production_admission=true` is always rejected.

## Services and persistent locations

| Component | Installed location / behavior |
| --- | --- |
| Existing STANDARD service | `defenderlink-mesh.service`; user defenderlink, NET_ADMIN-only, unchanged |
| Native Java application | `defenderlink-native-exporter.service`; installed `/opt/defenderlink/lib/defenderlink-mesh.jar`, NATIVE_DUAL/NATIVE, loopback API 8444 |
| Authorization Authority | `defenderlink-native-aa.service`; explicit mTLS credentials/pins, loopback endpoint configured by operator |
| Native supervisor | `defenderlink-native-supervisor.service`; owns newly created dlip-e/o/i/r namespaces, charon children, kernel hooks and pins |
| Native service entrypoint | `/opt/defenderlink/native/installed_runtime.py`; no packet/signing fixture imports |
| Compiled gate | `/opt/defenderlink/native/kernel_gate_v2.bpf.o`, built from existing unchanged C gate |
| Operator CLI | `/usr/bin/5gnexus native-start`, `native-status`, `native-stop` |
| Explicit profile | `/etc/defenderlink/native/deployment.json`, root-owned 0600 under root-owned 0700 parent |
| Live node identity | `/var/lib/defenderlink-native/node/identity`, root-private persistent Ed25519 node identity |
| Control spool | Explicit `control.directory`, normally `/var/lib/defenderlink-native/control`: 0600 approval/challenge/inbox/status/highwater/journal files |
| AA durable history | Explicit `aa.db`, normally `/var/lib/defenderlink-native/aa/authority.sqlite`, 0600 with private parent |
| Explicit tunnel PKI | `credentials` points to private e/o directories containing swanctl.conf, private/identity.pem, x509/identity.pem, x509ca/ca.pem (0600) |
| Runtime IPsec state | New private `/var/lib/defenderlink-native/transport-*/{e,o}` per service start; private VICI sockets and daemon logs |
| Kernel state | `/sys/fs/bpf/5gnexusguard-installed/{maps,progs}`; auth_map, health_map, verdict_map; TC wg_ingress/resource_ingress on owned inner wg-inner/resource devices |
| Independent nft hooks | Owned inner namespace `inet ipsec_dual` and `inet nexusguard_kernel_gate`, both default DROP |

No native unit is enabled or started by installation. Native units are separate
root prototype processes: only the supervisor receives the reviewed namespace,
network, BPF and daemon capability set. The default STANDARD unit gains no
privilege. Runtime requires root, KVM/QEMU, a pinned actual current kernel boot
UUID, exactly lo in the VM's root network namespace, and an explicit
`profile=DISPOSABLE_VM` with `production_admission=false`. It refuses to adopt
existing namespaces or pins. Never fake container markers to satisfy a guard.

The add-on installs narrow guest AppArmor extensions for its transport-role
configuration, VICI and swanctl PKI paths. It preserves existing local operator
policy content and reloads the guest profiles; it does not disable confinement.
The reload is guest-wide, while its new file permissions are narrowly scoped.

## Provisioning contract

The private deployment JSON has exactly these top-level fields:

`version` (integer 1), `profile`, `production_admission`, `boot_id`, `service`,
`client`, `owner`, `operator_key`, `supervisor_key`, `credentials`, `aa`, `control`.
Identity/public-key pins are 64 lowercase hex characters. Service is a literal
service ID. Operator and supervisor pins are distinct from the actual persisted
Java node identity. The mTLS node certificate must contain that same Ed25519
public key; it is not a replacement fixture identity.

`aa` requires `db`, `signing_key`, `node_pins`, `operator_pin`, `operator_key_pin`,
`server_cert`, `server_key`, `client_ca`, `port`. `node_pins` names a private JSON
mapping actual node IDs to certificate SHA-256 fingerprints; operator certificate
and public-key pins are separate. AA response signing identity is separate again.

`control` requires `directory`, `supervisor_key` (private PEM path), `aa_key`
(public response pin), `url` (explicit HTTPS attest URL), `ca`, `cert`, `tls_key`.
No private operator key is accepted by the Java exporter or installed supervisor.
All credentials are externally provisioned; deployed services do not create a
CA or approve themselves. The shared config module retains its historical lab
generator, but the installed entrypoint always supplies mandatory operator
credentials and never calls that branch.

The operator explicitly commits AA policy over pinned operator mTLS. A genuinely
new AA database accepts a first authorization transition; restart quarantines
existing state and requires fresh authenticated recovery followed by new policy.
The supervisor always starts denied and needs a separately signed native RECOVER
and fresh payload approval bound to its current signed challenge. Java signs only
that exact external approval using its persisted node key. Original BOOTTIME
deadlines (maximum three seconds) are never renewed from ledger refresh or by
restarting a service. Kernel health permits remain independently bounded to
500 ms and the original signed/AA deadlines.

`native-start` requests service startup; wait for readiness/status before issuing
approvals. `native-status` labels its publisher observation as cached, clears an
optimistic permit display on a stopped/stale publisher or elapsed authorization,
and does not replace per-packet kernel validation. `native-stop` stops the
supervisor first, revoking maps before tearing down owned topology, then stops
the exporter and AA. Restart does not silently restore authorization.

## Reproduce installed-service acceptance

Prepare a stopped private Ubuntu 26.04 cloud guest with the previously validated
base dependencies and a reviewed local offline dependency directory. The installed
demonstration used Linux 7.0.0-38, strongSwan 6.0.4 and WireGuard tools 1.0.20250521.
The exact matching local package/archive hashes are retained in each evidence
receipt. Do not install every archive from an unfiltered recursive dependency
download: use a dependency set resolved against this guest's saved dpkg status.

```sh
# New private output paths outside the checkout; cached Maven dependencies.
bash packaging/build-deb.sh /absolute/new-base-build
bash packaging/build-native-deb.sh /absolute/new-native-build
# Runtime approval must cover this new disposable VM before execution.
python3 -B scripts/operational/run_installed_dual_vm.py --parent-approved \
  --disk /absolute/stopped-qualified-baseline.qcow2 \
  --base /absolute/completed-base.deb \
  --native /absolute/completed-native-addon.deb \
  --dependencies /absolute/selected-offline-dependencies \
  --evidence /absolute/new-private-evidence
```

The runner validates archive payloads before staging, creates only a fresh overlay
backed by the saved disk, pins its SHA-256, attaches a read-only seed, and launches
only an owned QEMU with `-nic none` and private Unix QMP/serial paths. It never
operates libvirt VMs, opens host forwarding ports, or changes host networking.

The external `installed_dual_operator.py` is a test operator/observer, not an
installed product service. It refuses non-KVM/NIC-bearing/unseeded contexts before
package mutation, installs the real local packages offline, enrolls dedicated
test PKI against the actual Java identity, explicitly signs approvals, runs an
independent TCP echo resource, and records actual packet/counter evidence.
Transport, AA, signing, health and enforcement execute in the installed units;
no development packet harness/Fixture/JavaIssuer is substituted for them.

WireGuard/public/transit/resource captures stop and flush before topology removal.
Signed revocation tests existing/new flow denial while the topology is intact;
a retained old TCP socket is also tested after service stop. Restart is denied
before fresh AA/native recovery and a new approval. Each capture must exit cleanly
with zero drops. Cleanup checks pins/namespaces, owned QEMU termination, unchanged
baseline disk and normalized host snapshots independently of raw lifetime drift.
All private keys/disks/raw logs/captures stay outside Git.

## Acceptance scope

Run 08 passed complete installed prototype acceptance and independent review.
The tracked runner repeated every guest/service/packet case successfully, but
its separate strict host comparison flagged bridge-veth/IPv6-route changes and
therefore retained an overall FAIL. Neither result is rewritten. See the linked
executed evidence for hashes, packet counts and this audit distinction.

The test operator, AA and node services share one disposable root trust domain.
This is not independent key custody, whole-store rollback resistance, general
IPv6/external-gateway/performance qualification, or comprehensive installed crash
reconciliation. Production admission remains disabled and website readiness NO.
