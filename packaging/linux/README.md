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
interface checks and disconnect cleanup. Its original positive-only version ran
and failed; the expanded checks below require fresh approval. The export test
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
Privileged installation, real service lifecycle, successful STANDARD packet qualification, native
service integration, performance comparison and recovery qualification remain
outstanding. This milestone does not mark P2 working or P1 production-accepted.

STANDARD lifecycle corrections also have four focused Java regressions: full
scope interface naming, refusal to delete an existing name, kernel index/alias
ownership checks, and retained failed-teardown tracking. These have not yet
received packet sign-off. Ownership records remain process-local; crash
reconciliation and partial-creation recovery are outstanding operational gates.

## P2 execution at checkpoint 52d670c

The two approved commands were executed once, in order. No privileged retest
was performed after the first mandatory STANDARD failure.

**Evidence export: PASS.** The retained-state, NIC-free guest exported 538,989
bytes in 216,666,900 ns. All 81 immutable original artifacts matched SHA-256;
only the two reviewed startup logs were excluded. All 83 original reboot-test
artifacts in persistent evidence were independently verified unchanged. Guest
boot count was 3, boot ID `11a4725c-90c1-4c08-be70-fc5b1f65f859`; owned QEMU
exited 0. No P1 authorization/packet case was rerun. Raw snapshots differ in
address-lifetime countdowns; normalized host configuration was unchanged. The
original receipt's `raw_host_snapshots_equal=true` actually represented that
normalized comparison. The receipt is preserved; future reporting separates
raw equality from configuration equality and gates acceptance on the latter.

**STANDARD: FAIL.** Both real JVMs started, gossip discovery and both-node
registration passed, and `prototype-a` delivered its protected echo.
`prototype-b` then timed out. Both owner interfaces were distinct, and both
proxy listeners were established; interface-name collision was not this
observed failure. Both namespaces and the owned container were removed. Host
configuration was unchanged. Normal disconnect and denial were not reached.

Source and a nonprivileged authenticated-negotiation regression reproduced the
endpoint defect: a second owner listener allocated port 51821 but its response
still advertised the base endpoint port 51820. Initiator requests likewise
used the fixed base endpoint. Actual runtime WG endpoint state and packet
captures were not retained by that original driver, so the diagnosis is
source-backed and reproduced in regression, not an independent UDP trace.

The correction advances advertised ports with allocation while preserving an
explicitly configured first public port. Additional services assume a contiguous
forwarded public-port range; NAT forwarding is not qualified here. The owner
is authoritative for its advertised endpoint, which the connector validates
and preserves. No negotiation schema, authorization decision, native gate,
capability or protocol changes. The regression failed before correction and
all 37 focused Java tests passed afterward, including the existing native V2,
identity-permission and STANDARD lifecycle regressions.

The original STANDARD driver could not prove the requested authorization denial,
physical packet path, or post-disconnect residual denial. Its prepared replacement
requires disallowed-service membership rejection, an actual direct-underlay echo
attempt, seven zero-drop captures, matching TCP SYN/payload at both WG interfaces,
encrypted WG transport on the management link, kernel endpoints/listen ports and
handshakes, ownership/index records, and existing/new TCP denial after both
explicit disconnect APIs complete. It records the initial disconnect request
and successful in-flight attempts separately; no maximum revocation window is
claimed. The wrapper checks mandatory evidence, retains diagnostics even on
failure, and verifies owned cleanup and normalized host configuration.

These prepared checks have offline acceptance/syntax coverage only and require
fresh approval before execution. The original runtime FAIL is not converted
to PASS by the correction or by those tests. Independent review found no
remaining HIGH/CRITICAL issue in these corrections or the prepared acceptance
code. Existing STANDARD wildcard egress is an unresolved source concern to
exercise with the underlay-denial test; no exploit or denial result is claimed
from this run. Systemd installation/service recovery remain unperformed, and
P2 remains PARTIAL with production acceptance blocked.

## Corrected STANDARD retest at checkpoint 2d38a26

One explicitly approved corrected run was executed. Discovery, registration,
actual WG endpoints/listen ports and handshakes passed for both services on
51820 and 51821. Both protected TCP request/reply paths passed. Seven zero-drop
captures contain matching SYNs and application payload at both WG interfaces;
each management capture contains 24 encrypted WG transport packets.

**HIGH authorization bypass confirmed; runtime result FAIL.** The unauthorized
client's signed negotiation was rejected by the owner with 403, but a separate
plain TCP request to `192.0.2.2:15002` reached the protected application through
legacy egress. The unauthorized request and reply appear on both management
captures and application loopback, and on none of the WG captures. This is
actual underlay delivery, not a hypothetical source finding.

The root cause is `EgressProxy.syncEgressBindings()` automatically opening
`new ServerSocket(service.assignedPort())`, an any-local listener, merely because
a ledger service was active. That listener forwarded without checking the
incoming caller's authorization or tunnel. The narrowly scoped correction
removes automatic plaintext listener creation, withdraws obsolete owned
wildcard listeners, rejects any-local bind arguments, and preserves only the
explicit negotiated address-bound path. Failed closure remains tracked for
retry. A seeded unbound-socket regression failed before correction; all six
new proxy tests and all 37 existing focused Java tests passed afterward.
These unit cases do not open wildcard host listeners. Native-mode guards and
P0/P1 kernel enforcement remain unchanged.

No packet retest followed the mandatory failure. Normal disconnect/residual
checks were not reached. Cleanup itself passed: both JVMs exited on SIGTERM
(143), the application exited -15, both owned namespaces were removed and the
owned container was removed. Normalized host configuration stayed unchanged;
raw address-lifetime countdowns advanced. Captures, original JAR/source
fingerprints, reports and diagnostics are retained privately outside Git.

The correction has source/regression independent review, not runtime sign-off.
Withdrawing a listening socket is not revocation of already-forwarding sockets;
the corrected product must be restarted and existing/new flow disconnect tests
must still execute. An address bind is not ingress-interface enforcement, and
arbitrary routed access to WG addresses is not qualified by this assigned-port
test. No general underlay-denial or production-security PASS is claimed.

The prepared next run also records route/address/interface snapshots, listening
sockets, nftables rules and source-validation settings before/after relevant
phases. Those are read-only observations; it refuses to autoload host modules
and neither installs fallback routes nor changes enforcement to make a test
pass. This evidence addition and the corrected JAR require fresh approval
before another privileged run. P2 remains PARTIAL; runtime unauthorized/underlay
denial remain FAIL until a newly approved real packet test demonstrates denial.

Independent review confirmed the packet-level HIGH finding and approved the
narrow source correction and read-only evidence additions with no introduced
HIGH/CRITICAL findings. This is source/regression sign-off only; it does not
close the recorded runtime failure or qualify routed underlay access.

## P2 STANDARD capture lifecycle and packet acceptance (2026-10-31)

The 2026-10-30 run remains FAIL: deleting WireGuard interfaces before stopping
capture processes produced nonzero tcpdump exits. Its separately audited positive
traffic and assigned-port denial observations were not full capture acceptance.

The STANDARD harness now strictly finalizes each service's WireGuard captures
before either explicit teardown API can remove an interface. A failed flush
prevents normal teardown execution and fails acceptance; unexpected capture
errors and drops are not waived. Management and application captures survive
through both teardown calls and the denial window. Per-phase interface byte
statistics, pre-teardown WireGuard transfer counters, application forwarding-byte
counts and continuous established/new-connection probes provide separate teardown
evidence. A focused regression verifies flush-before-removal ordering and that
an unexpected capture failure prevents the teardown callback. All three offline
STANDARD acceptance regressions passed.

One approved corrected isolated run against the existing product JAR exited zero:
`P2_STANDARD_COMPATIBILITY=PASS`. Private evidence is retained at
`/home/wpotech/5gnexusguard-p2-bypass-20261031-01`; no credentials, captures or raw
runtime logs are committed. JAR SHA-256 remains
`48fb7728186f3af4412e2d97fc2be4c901fc1bbcbf7e77584b4b2ed876bc992d`.
No product transport, firewall, routing, authorization or port-allocation code
changed for this correction; the already accepted port milestone was not reopened.

Independent read-only source and packet review is PASS, with no introduced
HIGH/CRITICAL finding. Seven captures finalized cleanly with zero reported drops.
Each service has 14 protected SYN flows matched across both WG interfaces;
management captures each contain 565 encrypted WG transport packets and no
protected application marker. The assigned-port unauthorized SYN and matching
RST/ACK appear at both management boundaries, with no matching flow at WG or
application boundaries. The unauthorized application marker is absent.

After completed two-sided teardown, each service recorded 41 established-mode
and 44 new-connection attempts with zero successful forwarding. Application byte
counts stayed at 2082 and 4351 respectively through their denial windows; the
application capture independently totals 4351 request bytes. The review confirmed
no residual WG interfaces or proxy listeners, stopped owned processes, removed
owned namespaces/container, private evidence permissions and equal normalized
host configuration. Raw snapshots differ in lifetime countdowns. The 24 existing
tracked `target/` modifications were preserved.

This accepts the tested assigned-port plaintext bypass correction and completed
two-sided teardown behavior. It does not establish general routed access denial
to WG addresses, automatic owner cleanup from connector-only disconnect, or an
instantaneous revocation bound. P2 remains PARTIAL pending package installation,
systemd lifecycle and the other operational gates. Production security acceptance
remains BLOCKED and website readiness remains NO.
