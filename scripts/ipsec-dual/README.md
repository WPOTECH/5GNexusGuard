# Hybrid native Linux primitive and isolated packet lab

This directory implements IKEv2/ESP outer transport with inner WireGuard. The
unchanged `../native-dual/` directory is the WG-over-WG reference at `903684a`.
Read [architecture](../../docs/architecture/native-dual-tunnel.md) and
[results](../../docs/testing/native-dual-tunnel-results.md) before deployment.

Unprivileged build and checks, from the product checkout:

```sh
scripts/ipsec-dual/check.sh -o
python3 scripts/ipsec-dual/config.py --mode NATIVE
python3 scripts/ipsec-dual/config.py --mode EXTERNAL_CONFIG \
  --local 192.0.2.1 --remote 192.0.2.2 \
  --local-id endpoint.test --remote-id gateway.test
```

The renderer writes a strongSwan endpoint configuration to stdout and performs no
network operations. Replace documentation IPs and identities with operator-pinned
values. For the peer, reverse the public addresses, certificate identities, and
local/remote traffic selectors. Install `x509/identity.pem`,
`private/identity.pem`, and `x509ca/ca.pem` beside swanctl.conf using a dedicated
operator PKI. The profile requires mutual certificate authentication with exact
SAN matching, IKEv2 AES256-GCM/PRF-SHA384/ECP384, tunnel ESP AES256-GCM/ECP384,
and UDP/51821 selectors 10.77.0.1/32 <-> 10.78.0.2/32. A third-party gateway must
support that profile, route inner WG packets to 10.78.0.2 and enforce equivalent
fail-closed ACLs. This tool does not provision or validate an appliance. No pfSense
interoperability has been tested. Address selectors are intentionally bounded;
changing them also requires updating the firewall, routes and product service bind.

The native lab creates four `dlip-*` namespaces inside a single isolated Docker
container, runs two independent charon processes, generates ephemeral certificates
and WG keys, and initiates a real CHILD_SA. Credentials are generated only under
container `/tmp`, never in the checkout/image/evidence. The signing key is removed
after issuance, and all runtime credentials disappear with the container. Test
certificates are not a production enrollment mechanism.

**Privileged run requires explicit parent approval.** Only after approval, on a
disposable Linux Docker host with kernel WG, XFRM and nftables support:

```sh
scripts/ipsec-dual/run.sh --parent-approved /tmp/defenderlink-ipsec-evidence-001
```

The output directory must be new, absolute and outside the repository. The flag
prevents accidental runs; it does not itself establish approval. Do not run
`integration.py` directly on the host. No host route/firewall/sysctl changes or
host-network containers are used. The image build needs Debian package access;
the test container has no external network. No kernel modules are loaded.
See the architecture document for the six explicitly requested capabilities and
AppArmor relaxation. Default Docker seccomp is retained: if the host blocks a
required mount/unshare, record a blocked run rather than broadening privileges.

The launcher captures exit status, logs, image/container metadata, package versions,
public/transit/resource pcaps, IPsec SA counters/policies, WG counters and nft
rules. It removes its container and anonymous evidence volume after copying.
No private credentials or `ip xfrm state` key dumps are copied. Base tag and package
updates are not bit-for-bit pinned; retain the recorded image ID locally for exact
reruns. Do not treat missing artifacts or nonzero status as success.

Gates include nested TCP echo, packet-layer visibility, both encrypted layers'
counters, default denial, live wrong-port denial, public bypass, outer-origin
bypass, established-flow revocation, lease expiry, layer outage/recovery, SA
removal/recovery, wrong certificate identity, wrong inner key, and a restored
valid peer followed by an injected public fallback route. Per-fault baseline, failure, recovery and overlapping continuous pcaps now cover
all five boundaries in both directions, with before/after SA, route and nft
observations. Each baseline must deliver a live authorized echo. Owned endpoint
and gateway charon crash/restart and bounded in-flight revocation checks are
included; these cases passed the isolated `ipsec-dual-readiness-3` run (see
results), but have not passed full-product integration. The packet harness calls the timed set with synthetic
authorization; it is not a running product-ledger integration test.

For the local product adapter, set:

```properties
mesh.access.mode=NATIVE_DUAL
mesh.native.gateway-mode=NATIVE
mesh.native.service-id=<ledger service ID>
mesh.native.client-node-id=<64 hex client node ID>
mesh.native.lease-file=/private/lease.json
```

The service owner process writes leases into an existing owner-controlled mode-0700
directory. In a separately provisioned isolated runtime, `native.py --service ...
--client ... --owner ... --ledger-uid ... --credentials /private/operator-pki
--lease /private/lease.json --state
/tmp/hybrid-state` consumes that file and renews enforcement. State must be private,
root-owned, outside git and outside `/run`; the daemon privately mounts `/run`.
The native CLI requires operator PKI; only the integration harness generates test PKI.
Use a root-owned mode-0700 credentials directory with `e/` and `o/` profiles, each
containing `swanctl.conf`, `private/identity.pem`, `x509/identity.pem` and
`x509ca/ca.pem`, all root-owned mode 0600, with no symlinks. Supply reciprocal
certificate identities and the fixed selectors described above. The CLI copies
these into private runtime state and leaves original credentials unchanged.
It still provisions only the bounded namespace topology, not multi-host packaging. The Docker packet launcher does not mount a product lease or
start the Java product. Operator packaging and an end-to-end product lease test
remain pending; Java mode alone cannot create a tunnel. `EXTERNAL_CONFIG` suppresses
lease export while retaining STANDARD guards, so it cannot imply local enforcement.

For STANDARD under an AppArmor profile that attaches to `/usr/bin/wg` and only
allows reads from `/etc/wireguard/{,**}`, configure the optional
`MESH_TUNNEL_CONFIG_DIR=/etc/wireguard/defenderlink` and provision that directory
as real, mode-0700, owned by the JVM's effective user. The JVM must be able to
write it and the actual `/usr/bin/wg` must be able to read it. Identity and ledger
stay in `mesh.data-dir`; without this override the existing `wg-configs` path is
preserved and an owned legacy default directory is tightened to 0700 before new
keys are written. A distinct service UID needs the leaf provisioned in advance
with traversal permission through `/etc/wireguard`, but no shared-writable
ancestor. Do not globally disable AppArmor, widen private-key modes, or copy the
`wg` executable to evade its profile. Test the exact deployed profile and path;
other hosts can have different policy.

Normal failures clean up owned namespaces and processes. Container deletion is the
final cleanup boundary. An interrupted standalone supervisor can leave namespace
state: it refuses to adopt existing names, rather than deleting unknown state.

Read the [bounded security review](../../docs/testing/native-dual-tunnel-security-review.md)
for supervisor fixes, evidence semantics and explicit BLOCKED acceptance work.
DNS-dependent failure, runtime certificate expiration, full exporter/supervisor
races and full-product integration remain unresolved. Certificate expiration must
not be inferred from lease expiry or wrong-identity rejection. No production
readiness is claimed by the unprivileged regression suite:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/ipsec-dual -p 'test_*.py' -v
```

The supervisor now samples lease lifetime after health checks, verifies both owned
charon processes are alive, revokes access before bounded daemon recovery, and
restores exact owned routes even when a wrong route exists. Recovery never issues
new credentials, widens selectors, or relaxes ACLs. Kernel SAs may survive daemon
death; fail-closed crash handling depends on supervisor detection and the timed
lease. See the review for remaining timing and readiness limits.

## Functional P0: signed V2 authorization and active-grant denial

`run_functional_p0.py` runs only the functional grant scenario in the reviewed
`dl-ipsec-isolated-evidence:probe` image. It creates the isolated topology,
connects Java exporter → mTLS Authorization Authority → native supervisor →
BPF maps, validates the packet path, disconnects, and removes its namespaces,
pins, container and temporary evidence volume. It never enables production
admission or runs the separate fault-injection sequence. STANDARD remains the
default; DUAL_TUNNEL remains opt-in.

Prerequisites on Polaris: Docker access, JDK 25, Maven, Python with cryptography,
and the existing reviewed image. The image includes clang, libbpf/bpftool,
iproute2/TC, nftables, strongSwan, WireGuard, tcpdump and Java 25. Its locally
validated image ID is
`sha256:ecd5c54a5243526f0fde27f061fca30a13e5911e855f6108b348f4b8787ce54e`.
The existing `isolated-enforcement.Dockerfile` extends the reviewed
`dl-ipsec-bpf-java25:probe` base; no privilege expansion or host networking is
needed. An image tag alone does not establish equivalent host/kernel behavior.

Prepare Java artifacts in a new scratch build, preserving the checkout's
existing generated `target/` files. From the repository root:

```sh
umask 077
JAVA_BUILD=$(mktemp -d /tmp/mesh-p0-java.XXXXXX)
cp -a pom.xml src scripts "$JAVA_BUILD/"
mvn -B -f "$JAVA_BUILD/pom.xml" \
  -Dtest='com.defenderlink.mesh.tunnel.nativeaccess.*Test' test
mvn -B -f "$JAVA_BUILD/pom.xml" dependency:copy-dependencies \
  -DincludeScope=test -DoutputDirectory="$JAVA_BUILD/target/lib"
# These contain compiled test code/dependency jars, never runtime credentials.
# The capability-dropped container needs read access to the mounted directory.
chmod a+rx "$JAVA_BUILD/target"
chmod -R a+rX "$JAVA_BUILD/target/classes" \
  "$JAVA_BUILD/target/test-classes" "$JAVA_BUILD/target/lib"
```

Obtain explicit runtime approval for the scoped Docker run first. Then start,
connect, validate, disconnect and clean up with this single command (choose a
new absolute evidence path outside the repository):

```sh
python3 scripts/ipsec-dual/run_functional_p0.py --parent-approved \
  --java "$JAVA_BUILD/target" --evidence /tmp/mesh-p0-evidence-001
```

The flag guards accidental execution; it is not a substitute for approval.
The launcher retains `--network none`, the reviewed eight capabilities,
AppArmor setting, resource limits, read-only source/Java mounts and private
credential tmpfs. Raw output, nft JSON and pcaps stay in the mode-0700 evidence
directory, with captured files mode 0600. It prints only the evidence location
and an acceptance summary. Inspect status locally:

```sh
cat /tmp/mesh-p0-evidence-001/acceptance.json
```

Exit zero and `PROTOTYPE_P0=WORKING` require all of the following:

- Zero authorization/health maps and measured pre-grant BPF denial.
- Genuine signed RECOVER, Java V2 issuance, AA attestation and supervisor approval.
- Exact original BOOTTIME authorization deadline and bounded live health map.
- Both named TC programs attached and both independent nft forward hooks verified.
- Positive TCP echoes and a matching SYN across all four protected boundaries.
- A scoped resource ARP reply, encrypted WireGuard transit and ESP-only public
  directional IPv4 egress.
- A wrong-port SYN arriving through WireGuard and being denied at WG ingress;
  a wrong-resource-source SYN denied at resource ingress; and an unencapsulated
  valid protected tuple denied on direct transit by nft. Exact packet identities
  must appear before enforcement and be absent after enforcement. AF_PACKET
  injection exercises these ingress checks without broadening endpoint output
  rules, changing routes, or creating a fallback path.
- Successful authorized echoes both before and after those negative probes,
  unchanged authorization, both TC scope-denial counters, and the nft drop counter.
- Zero capture drops; successful map revocation and cleanup; no remaining named
  namespaces or BPF pins; successful container and temporary-volume removal.

The checker normalizes only the observed nft conntrack form
`{"op":"in","left":{"ct":{"key":"state"}},"right":"established"}`.
It retains exact interfaces, tuple, TC mark, counter, hook priority and default
DROP requirements. Multi-state sets and membership tests on other fields are
rejected. No nft rule or packet-path policy was changed for this correction.

This is functional P0 acceptance for the isolated prototype. Production security
acceptance remains **BLOCKED** pending independent authorization rollback,
revocation and daemon-crash validation. No website or deployment change follows
from this result. Keep raw evidence local and outside Git.

Validated on Polaris with the reviewed image: 69 positive baseline echoes and
60 active-grant echoes, all successful; 15 completed before the negative-probe
window and 24 began after it. The WG and resource TC scope-denial counters each
increased by one, and the direct-transit nft drop counter increased by one.
The labeled negative packets were observed only on their expected pre-enforcement
boundaries. Public directional egress contained 149/143 ESP packets and no
cleartext IPv4; all ten captures reported zero drops. The scoped ARP reply and
pre-grant denial passed, both TC hooks remained attached, the exact nft rule
checks passed, and all cleanup stages left no namespaces or pins. These are
isolated functional measurements, not production security acceptance.

## P1: isolated expiration and signed revocation (partial qualification)

P0 reference: `4a379415ac4577d36c316d16afe1b8d508252c5f`. The P0 command above
remains the default; P1 requires an explicit single-category selector and separate
runtime approval. Production admission remains disabled. From the same prepared
Java/image environment, after approval, run expiration first:

```sh
python3 scripts/ipsec-dual/run_functional_p0.py --parent-approved \
  --p1-scenario expiry --java "$JAVA_BUILD/target" \
  --evidence /tmp/mesh-p1-expiry-001
```

Only if expiration passes, run signed revocation in a fresh container:

```sh
python3 scripts/ipsec-dual/run_functional_p0.py --parent-approved \
  --p1-scenario revoke --java "$JAVA_BUILD/target" \
  --evidence /tmp/mesh-p1-revoke-001
```

Each scenario uses the unchanged P0 isolation and enforcement, a genuine Java
V2 grant, simultaneous persistent-connection and new-connection echo workers,
ten packet captures, authorization/health map snapshots, a map-write audit,
TC/nft counter snapshots, and verified cleanup. The test checks that every live
authorization write retains the original deadline. No wall-clock change,
manual map grant, alternate route, or automatic reauthorization occurs.
`security_p1.py` records a BOOTTIME-to-MONOTONIC sampling interval for expiry;
revocation timing starts immediately before the signed operation and ends after
its normal publisher reconciliation. Application verdicts include scheduling
and the approximately 80 ms socket timeout, not just kernel enforcement latency.

Observed on Polaris, with the same reviewed image as P0:

| Scenario | Worker | Last successful verdict relative to event start | First denied attempt | First denied verdict |
|---|---|---:|---:|---:|
| Original deadline expiry | Established | -0.840 ms | +9.478 ms | +90.199 ms |
| Original deadline expiry | New connections | -1.699 ms | +8.512 ms | +89.179 ms |
| Signed revocation | Established | +23.959 ms | +34.076 ms | +114.296 ms |
| Signed revocation | New connections | +24.142 ms | +34.290 ms | +114.592 ms |

The expiry clock-conversion sampling interval was 0.0017 ms. Signed revocation
processing/reconciliation completed 38.647 ms after its event start. Traffic
therefore continued briefly during revocation processing; instantaneous
revocation is not claimed. No successful attempt began after the respective
completed event/deadline, and no delivery returned after the first denial.

Expiry recorded 43 map-write attempts with no failures, one TC authorization-
deadline denial and subsequent authorization-missing drops. Revocation recorded
40 map-write attempts with no failures and authorization-missing drops. Both
runs retained both TC hooks, read back zero auth/health maps after denial,
verified matching TCP SYNs across all four protected boundaries, recorded ten
zero-drop captures, and completed all six cleanup stages with no namespaces or
pins remaining. Host network namespace, addresses and routes were unchanged
across the recorded checks. Raw maps/audits, pcaps and logs stay in private local
evidence directories and must not be committed.

These runs qualify **normal expiry and successful signed revocation only**.
Failed map writes/uncertain revocation, independent heartbeat expiry under
userspace failure, charon crash with surviving XFRM SAs, rollback/replay,
restart/recovery and independent P1 security review remain unqualified. The
observed intervals are samples, not guaranteed maximum security bounds. Overall
P1 and production security acceptance remain incomplete/blocked respectively.

## P1.3: retained-map kernel enforcement (experimental qualification)

Baseline: `6ff60b5d8e4bc1af8c8712b6d06ab41cfeb92780`. The test-only
`p1_supervisor_process.py` runs the existing Controller, Publisher and FreshHealth
in a separate process. AA, Java, captures, the application and both charon
processes remain outside it. Private supervisor credentials travel over stdin,
never argv or evidence. The child verifies the actual TC program IDs, exact nft
interlocks and zero maps before taking over; it starts a fresh denied session
and requires genuine signed RECOVER plus Java V2/AA approval. No production
entry point or enforcement policy is changed.

After explicit scoped runtime approval, use the same Java/image preparation as
P0 and run these categories in order, with fresh evidence directories:

```sh
python3 scripts/ipsec-dual/run_functional_p0.py --parent-approved \
  --p1-scenario supervisor_failure --java "$JAVA_BUILD/target" \
  --evidence /tmp/mesh-p13-supervisor-001
# Only if supervisor failure passes, and approval includes this category:
python3 scripts/ipsec-dual/run_functional_p0.py --parent-approved \
  --p1-scenario map_update_failure --java "$JAVA_BUILD/target" \
  --evidence /tmp/mesh-p13-map-update-001
```

The supervisor fault verifies PID, process start identity and container network
namespace before SIGKILL. No graceful handler can clear the maps. Both nonzero
auth/health entries must remain identical from the post-kill snapshot through
the full observation window. The test waits beyond both original deadlines,
requires both TCP modes to stop, and requires actual TC health-deadline and
authorization-deadline rejection counters. AA and charon must remain alive.

The map fault freezes only the owned auth/health maps, creating real kernel
`Operation not permitted` update errors. A genuine signed revoke and explicit
reconciliation must report uncertainty, never successful publication. The stale
nonzero entries must remain unchanged until observation finishes beyond their
original deadlines. A failed revoke does not immediately remove exposure.

Only after those measurements and the original authorization expiry does the
map-fault test recover: remove the expired frozen map pins, reinstall the same
gate under the still-present native priority-0 default-DROP interlock, and start
a fresh supervisor session. Old signed authority must leave the gate denied;
new signed recovery, Java V2 approval and AA attestation must precede resumed
traffic. Replacing expired lab maps is test lifecycle recovery, not production
recovery qualification. No alternate route or enforcement engine is added.

Measured Polaris results, relative to SIGKILL or the start of map freezing:

| Fault | TCP mode | Last successful attempt | Last successful verdict | First denied attempt | Denied verdict |
|---|---|---:|---:|---:|---:|
| Supervisor SIGKILL | Established | 370.338 ms | 371.201 ms | 381.416 ms | 461.720 ms |
| Supervisor SIGKILL | New | 371.533 ms | 373.560 ms | 383.662 ms | 463.878 ms |
| Frozen-map update failure | Established | 290.494 ms | 291.305 ms | 301.516 ms | 381.831 ms |
| Frozen-map update failure | New | 286.147 ms | 287.904 ms | 298.041 ms | 378.417 ms |

The retained health deadlines were +375.860 ms and +297.027 ms respectively;
the original authorization deadlines were +2621.327 ms and +2559.271 ms.
Each health entry retained its original 500 ms validity from its checked time.
No successful attempt or verdict was observed beyond the applicable health
deadline. Both scenarios recorded 49 TC health-deadline and 15 TC auth-deadline
SYN rejections, with zero auth-missing/health-missing rejections in the measured
window. Both nonzero maps and both TC hooks survived unchanged through expiry.
Neither loss of the supervisor nor rejected writes removed XFRM SAs: each
endpoint retained two, while AA and charon stayed alive.

The map test recorded three kernel-rejected updates and persistent
`revocation_uncertain=true` across three reconciliations. Its residual forwarding
window ended at the retained heartbeat deadline; immediate revocation is not
claimed. Old authority replay stayed denied during recovery. Fresh signed
generation 5 in a new session restored 12 established and 10 new TCP echoes.
The deliberate direct-underlay probe was seen on transit, incremented the nft
DROP counter once, and was absent at the protected resource.

Independent offline packet parsing paired 77 successful application echoes per
scenario with their worker timestamps. Observed packet/monotonic alignment
intervals were 63.011 and 56.718 microseconds wide. No protected client packet
was seen at the resource beyond the retained health deadline during either
original observation window. Directional public egress was ESP-only (no
cleartext IPv4), and transit carried WireGuard UDP except the labeled negative
probe. Fresh recovery traffic was assessed separately from expired authority.
All ten captures per scenario reported zero drops; all cleanup stages passed
with no remaining namespace or pins. Raw packets, failed-update stderr, maps
and credentials are not committed.

These are measured kernel fail-closed results, not proven maximum bounds.
Application denial verdicts include roughly 80 ms socket timeout plus scheduling;
limits assume the reviewed BPF program and exclusive trusted ownership of maps,
TC/nft hooks, namespaces and clock sources. Privileged tampering is outside this
experiment. Full P1 qualification and production security acceptance remain
separate gates; rollback/replay/restart and broader
recovery guarantees are not inferred from these two scenarios. Production
admission remains disabled and the website is unchanged.

Independent P1.3 review completed on 2026-10-24 for commit
`6e26c413fbd974601750e8f598c5917a3af59bae` and the two saved experiments.
A separate read-only reviewer inspected the implementation and actual private
evidence, independently parsed the packet metadata, and found no HIGH or
CRITICAL issues. P1.3 independent review is **PASS**, scoped to the measured
kernel fail-closed behavior and stated trust assumptions. No privileged rerun
was needed. One nonblocking LOW was recorded: `Supervisor.close()` did not surface
a nonzero graceful child exit status; the reviewed runs were protected by the
separate outer cleanup/readback checks. This sign-off does not qualify rollback,
replay, reboot freshness or production deployment.
The P1.4 packet-driver work below resolves that observability finding with
explicit unexpected-exit and graceful-timeout checks.

## P1.4 preparation: rollback, replay and reboot freshness

P1.3 independent review is complete. Preparation at `a054882` established the
control-plane regressions below. The subsequently approved P1.4 packet cases
are recorded in the next section; **actual reboot qualification remains blocked**.
No host clock or boot ID was changed and no P1.3 packet rerun was needed.

`test_freshness_p14.py` uses the real Java exporter and loopback mTLS AA with
throwaway fixture keys. Twelve focused controls cover duplicate issuance without
deadline extension, revoked-generation replay, correctly signed stale generation,
supervisor restart, exporter restart without receiver-floor reset, prior-boot
replay, boot binding with the same live nonce/generation, missing high-water
state, rolled-back high-water state, combined local journal/floor rollback,
controller-local wall-clock rollback, and fresh-authority recovery after clock
quarantine. Invalidly scoped negative envelopes have real test operator/node
signatures; the boot-only test then accepts the original genuine Java envelope
as its positive control.

Run these unprivileged preparation checks after the existing scratch Java build:

```sh
TEST_CLI_CLASSPATH="$JAVA_BUILD/target/test-classes:$JAVA_BUILD/target/classes:$JAVA_BUILD/target/lib/*" \
  python3 -m unittest discover -s scripts/ipsec-dual -p test_freshness_p14.py -v
```

The initial wall-rollback control demonstrated that the supervisor continued
reporting cached `ATTESTED` authority when only its own clock view moved back
60 seconds. The original BOOTTIME grant was still bounded; this was a missing
freshness quarantine, not an extension of kernel permissions. The correction
adds an instance-local wall source and a per-session millisecond high-water
check in Controller. Observed backward or invalid wall readings clear cached AA
deadlines and latch denial. Returning the clock forward cannot revive the
session. A new supervisor session, signed RECOVER, fresh Java approval and AA
attestation are required. No BOOTTIME deadline is resampled and no BPF/nft or
STANDARD default is changed. The clock source is local to the Controller;
AA/TLS clocks and the host time module remain untouched by the tests.

A separate reviewer found no HIGH or CRITICAL regression in this narrow
correction and independently ran the original eleven controls plus the added
boot-only binding control. The broader 277-test regression suite, the added
boot-only test, all twelve focused controls, and eighteen Maven native-access
tests passed. Maven output was built in scratch storage, preserving the
checkout's generated `target/` changes.

Packet validation uses scoped runtime approval and the existing isolated
harness, one freshness category per fresh container, with a real authorized
baseline, measured denial of both TCP modes, normal Controller/Publisher
handling and a fresh signed recovery baseline. The modeled
boot-ID tests do not constitute an actual reboot or prove kernel boot-reset
behavior. Likewise, restored local-state tests demonstrate denial of stale
proof, not a tamper-proof persistent monotonic anchor. Full P1 and production
security acceptance remain incomplete; production admission stays disabled.

## P1.4 packet validation: scoped non-reboot results

Nine explicitly approved cases completed once each on Polaris using the same
reviewed Docker image, `--network none`, eight capabilities, AppArmor setting,
read-only source/Java mounts and credential tmpfs as P0. No packet case failed
or needed a rerun. The test-only driver is `freshness_packet_p14.py`; none of
its fault controls is a production admission path. Clock offset and paused
publication hooks require the private child's explicit P1.4 fixture flag.
Kernel enforcement, native authorization protocol and STANDARD default are
unchanged.

After separate runtime approval, reproduce a single case with the existing
Java/image setup, selecting exactly one category and a new evidence directory:

```sh
python3 scripts/ipsec-dual/run_functional_p0.py --parent-approved \
  --p1-scenario p14_wall_rollback --java "$JAVA_BUILD/target" \
  --evidence /tmp/mesh-p14-wall-001
```

The other reviewed selectors are `p14_envelope_replay`, `p14_operation_replay`,
`p14_stale_generation`, `p14_duplicate_issuance`, `p14_supervisor_restart`,
`p14_highwater_missing`, `p14_highwater_rollback` and `p14_epoch_mismatch`.
The approval flag alone never establishes permission to run them.

Every case requires a live original authorization/heartbeat baseline immediately
before the fault, both established and fresh TCP connections, positive actual
TC rejection counters during denial, exact unchanged TC/nft hooks, a counted
direct-underlay rejection, and new-session signed RECOVER plus genuine Java
V2/AA approval before positive recovery. Invalid submissions must not publish,
advance the receiver generation floor or install an authorization deadline.
High-water faults may leave a nonusable cached admission deadline, but cached
AA proof must be zero and actual kernel permits must be cleared. The epoch
case deliberately changes only the owned health-map epoch while publication is
paused; an actual epoch-rejection counter must be read before health expiry.

Observed timing below is milliseconds from the recorded fault-request window
start. Each E/N pair means established/new TCP. Request windows include queued
health checks, RPC/fault setup and reconciliation; the epoch map mutation occurs
inside that window. Verdicts include approximately 80 ms socket timeout.
These are observed application intervals, not instantaneous revocation or proven
maximum kernel bounds.

| Case | First denied attempt E/N | Denied verdict E/N | Actual TC denial evidence |
|---|---:|---:|---|
| Local wall rollback/restoration | 130.793 / 131.022 | 211.045 / 211.372 | 50 auth-missing |
| Old/revoked envelope replay | 122.488 / 126.185 | 202.780 / 206.531 | 12 auth-missing |
| Signed REVOKE/RECOVER replay | 96.806 / 93.571 | 177.108 / 173.849 | 14 auth-missing |
| Correctly signed stale generation | 132.851 / 133.169 | 213.105 / 213.453 | 12 auth-missing |
| Duplicate issuance with live nonce/new generation | 125.782 / 118.943 | 206.062 / 199.241 | 11 auth-missing, 1 health-missing |
| Supervisor SIGKILL/restart | 396.501 / 403.808 | 476.800 / 484.126 | 5 health-deadline, 37 auth-missing |
| Missing high-water state | 129.279 / 138.459 | 209.629 / 218.711 | 12 auth-missing |
| Rolled-back high-water state | 137.322 / 130.004 | 217.524 / 210.294 | 11 auth-missing, 1 health-missing |
| Mismatched health enforcement epoch | 268.061 / 268.776 | 348.296 / 349.018 | 12 epoch/scope rejections |

The supervisor-local -60-second wall fault latched denial even after restoring
its clock view; the observation continued beyond the original authorization
expiry. Neither host time nor AA/TLS clocks were changed. Original successful
authorization-map writes retained exactly the signed deadline in every case;
invalid authority never extended it. Fresh authority in a new session restored
both TCP modes in all nine cases (195 recovered echoes total).

Restart retained unchanged nonzero maps through actual kernel health expiry
before a denied ownership handoff. The previous, still-unexpired Java envelope
was rejected 551.524 ms before its original authorization deadline, then fresh
signed authority was required. The epoch counter was observed 487.406 ms before
heartbeat expiry, isolating epoch rejection from ordinary timeout. High-water
repair used the fixture's trusted pre-fault snapshot; this is explicitly **not
independently protected AA rollback resistance** or an external monotonic anchor.

A separate read-only reviewer independently inspected implementation, all nine
packet/application evidence sets and lifecycle state. It correlated 92–141
successful echoes per case and found no protected client requests at the
resource after each completed-denial/restart-health bound in the original
observation window. Public directional IPv4 egress was ESP-only. Every labeled
underlay probe was seen on transit, incremented nft DROP once, and was absent
at the resource. Every case preserved both TC identities and exact nft
interlocks. All 90 timestamped captures reported zero drops; all namespace,
pin, container and volume cleanup checks passed. Raw evidence remains local,
with directories mode 0700 and files mode 0600; it is not committed.

Independent P1.4 scoped review is **PASS with no HIGH/CRITICAL findings**. The
prior graceful-exit LOW and the three pre-run acceptance gaps (live baseline,
physical TC rejection, pre-expiry epoch proof) are resolved. All 284 Python
regressions and 18 Maven native-access tests passed; Java builds stayed in
scratch and the user's `target/` changes were preserved.

Host-audit limitation: one initial aggregate read-only comparison differed
before its after-snapshot was retained; its cause is unknown. Three subsequently
saved comparisons match the recorded namespace, all 132 raw route rows and
interface-address configuration. The reviewed commands contain no host
network-write operation and isolation is unchanged. These later matches do not
reconstruct the unretained difference or prove continuous host-state immutability.
No privileged rerun was performed to replace that missing historical evidence.

**Actual reboot freshness remains BLOCKED.** QEMU/KVM and registered existing
lab VMs were found, but no disposable reboot target was identified or authorized.
No VM or host was rebooted; neither supervisor restart nor modeled boot-ID tests
are substituted for reboot qualification. P0 and prior P1 milestones remain
preserved. Overall P1 stays PARTIAL, production security acceptance stays
BLOCKED, and no website or Cloudflare changes are authorized by this milestone.

## P1.4 actual guest reboot: scoped packet qualification

The approved disposable KVM guest completed an actual Linux reboot using only
local assets. Baseline `08998312aad0d9dc5f75661faec37b5d956c5cac` and production
enforcement sources remain unchanged. QMP confirmed four vCPUs and 6 GiB RAM;
`-nic none` and a guest loopback-only assertion excluded a network adapter.
Only a new private virtual disk and private Unix management sockets were used.
Existing libvirt VMs, including powered-off pfSense, were not operated.

The staged local `7.0.0-38-generic` kernel SHA-256 was
`9f55ef7253055a9cf68f8a04323c93dead2fca617386d842fbde9ca7b178b27e`.
The reviewed Docker image was imported offline inside the guest, retaining the
existing packet harness's isolation and capability set. Persistent host disk
space was insufficient for the disposable disk, so it remains in the private
`/tmp/mesh-reboot-vm-lab-03` directory. This survives a guest reboot, but is not
storage that survives a Polaris reboot. Compact evidence was recovered to
private persistent scratch storage; no captures, credentials or VM images are
committed. An initial pre-authorization bootstrap failed because the minimal
guest's Docker client selected `/var/run/docker.sock`; explicitly selecting
`unix:///run/docker.sock` corrected it. The same guest disk was retained.

Observed qualification:

| Check | Actual result |
|---|---|
| Kernel boot identities | `ac1c1334-7f62-46bd-9b56-21d362772c5d` → `b54afcde-0d98-4886-9fa5-7dc63b6a86d0` |
| Authorized TCP before reboot | 24 established-mode and 19 new-connection echoes |
| Retained state | Same admission journal, AA high-water and SQLite checkpoint hashes; retained signing/TLS identities |
| Before fresh BPF installation after reboot | No old gate maps/programs; new authorization and health entries zero |
| Old envelope and recovery-message replay | Both DENIED; generation stayed 2, unpublished, no admission deadline |
| Stale-authority packet probes | 3 denied attempts per TCP mode; 12 ingress `auth_missing`/SYN drops including pregrant probes |
| Fresh authenticated recovery | AA recovery and new authorization advanced generation 1→2 and epoch 1→3; native signed recovery/authorization advanced generation 2→4 in a new session |
| Recovered TCP | 23 established-mode and 18 new-connection echoes |
| New kernel enforcement epoch | `14693578472637895514` → `11746358507351119182`; matching authorization/health bindings per boot |
| Physical evidence | 20 captures, zero kernel drops; 259/252 WireGuard transit packets before/after, ESP-only public IPv4 egress, protected-path SYN matches |
| Interlocks and bypass | Both TC hooks and scoped nftables rules intact; independent forward/reverse counters increased; direct underlay probe dropped each phase |
| Cleanup | Six stages PASS, namespaces and pins empty; owned QEMU exited 0 |

Original TCP sockets do not survive a guest reboot. “Established-mode” after
reboot means a newly created persistent connection, not continuation of an old
socket. Old authority also had obsolete BOOTTIME/session bindings: this test
demonstrates rejection across an actual reboot, without isolating boot-ID
validation from every other freshness check.

The preboot map-write audit contains no successful permit clearing after grant
and no extension of the original authorization deadline, 46.179487209 seconds
BOOTTIME. Reboot was requested at 44.183070340 seconds; the kernel logged restart
at 44.646682 seconds and machine restart at 44.648622 seconds. The last recorded
health deadline was 44.478629917 seconds, so it elapsed during kernel shutdown.
This establishes retained nonzero entries and a live authorization lifetime at
reset; it does not claim a live health permit at the physical reset instant.

**The original automation result remains FAIL**, separately from the offline
packet audit PASS. Virtio evidence export timed out. Evidence was recovered from
a stopped-disk copy after replaying the copy's filesystem journal; the original
disk was preserved. The control writer now handles partial device writes, with
a focused short-write regression, but that transport correction has not been
retested in a VM. No privileged packet test was repeated to fix reporting.

Saved host snapshots are **not identical**: one Docker veth disappeared and two
appeared, with three removed and six added kernel IPv6 routes on those exact
interfaces. Existing interface configuration, host boot ID, rules and libvirt
VM states were unchanged. Read-only Docker events corroborate concurrent bridge
connect/disconnect activity. The lab issued no host network write and had no
NIC; nevertheless exact host-wide invariance is not reported as PASS, and the
runner's conservative failure is preserved. Full operational automation remains
partial pending successful export and host-audit completion in a quiet window.

Reproduce offline preparation and audit using the scripts in `reboot_vm`:

```sh
# VM launch/reboot requires separate explicit operator approval.
python3 scripts/ipsec-dual/reboot_vm/build_guest.py \
  --directory /tmp/mesh-reboot-vm-lab-NEW --java "$JAVA_STAGE"
python3 scripts/ipsec-dual/reboot_vm/run_guest.py --parent-approved \
  --directory /tmp/mesh-reboot-vm-lab-NEW
# Read-only audit; no Docker, VM, network, or map writes:
python3 -B scripts/ipsec-dual/reboot_vm/audit_reboot.py "$PRIVATE_EVIDENCE"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/ipsec-dual -p test_reboot_vm.py -v
```

The offline audit binds worker records, map-write audit, actual captures,
TC/nftables snapshots, retained-state hashes and cleanup evidence. It emits
packet qualification separately from the original runner status and host
snapshot comparison. Baseline regressions passed: 284 Python tests (14 skipped)
and 18 Maven native-access tests; five new offline acceptance tests passed.
Java builds remained outside the checkout's generated `target/` files.

This does not implement or qualify an independently protected AA whole-store
rollback anchor. Production admission remains disabled; production security
acceptance and website updates remain blocked.

Independent review of the executed reboot artifacts is **PASS for scoped reboot
freshness and packet enforcement, with no remaining HIGH/CRITICAL findings**.
The reviewer independently parsed the captures (20/19 common protected SYN
flows before/after) and corroborated retained-state freshness, denied replay,
fresh signed recovery, BPF initialization and cleanup. This sign-off preserves
the original runner FAIL and operational PARTIAL status; it does not assert
exact host snapshot invariance or production security acceptance.
