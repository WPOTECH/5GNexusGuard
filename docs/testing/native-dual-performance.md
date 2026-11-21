# Installed STANDARD versus DUAL_TUNNEL performance qualification

Status: **FAIL — stopped at a mandatory DUAL health-coverage failure** during
the approved NIC-free VM execution. The comparison is incomplete; the values
below are diagnostic observations, not a performance qualification.
Baseline: `a8ec0d0`, feature branch `feat/native-dual-tunnel-access`.

## Execution scope

Use a fresh writable overlay over the retained Linux installation baseline,
4 vCPUs, 4 GiB RAM, host CPU model, no guest NIC and a read-only offline seed.
Private veth links/network namespaces live exclusively inside the guest. The
original disk, existing libvirt VMs, pfSense, Polaris network configuration and
previous evidence remain unchanged. Install only the already verified base and
native add-on archives/dependencies. No iperf3 installation is needed: the
standard-library workload provides receiver-verified application TCP echo goodput.

Use actual installed STANDARD services/JAR with two real identities, discovery,
registration, allowlisted exposure and connect/disconnect. Preserve the installed
unit's service identity, permissions and capability limits in isolated instances.
DUAL_TUNNEL uses the installed Java exporter, mTLS AA, native supervisor, managed
strongSwan gateway, WireGuard, TC/eBPF and nftables under its existing NIC-free
profile. The pfSense interoperability baseline is preserved; this comparison
uses the already validated managed gateway to avoid adding a separate gateway
VM's resources to only one arm.

Measure a separately labeled isolated unencrypted application path for context;
it is not a product configuration or a production security mode. Never dismantle
a protected mode's enforcement to obtain that context path.

## Comparison contract

Use the same guest allocation, workload implementation, source/resource roles,
payload sizes and 0.5-second measurement windows, three planned repetitions per cell (stopped in the first repetition).
TCP stream counts are 1 and 4; goodput blocks are 4,096 and 65,536 bytes;
request/response messages are 64 and 4,096 bytes. Balance STANDARD/DUAL and
DUAL/STANDARD ordering across blocks and interleave the unencrypted context.
Record host load and guest CPU/memory conditions for every block; do not stop
unrelated workloads or claim dedicated hardware.

The short window is intentional: native authorization has a three-second maximum
and the established test grant lasts 2.501 seconds including issuance processing.
Every timed DUAL sample requires fresh separately signed authority, verified
original deadlines and sufficient remaining margin. Never silently renew or
extend a signed grant. Apply the same timed duration to STANDARD and context.
Report short-window variation rather than claim sustained-rate qualification.
There is no warmup: every arm uses fresh TCP connections, with setup timed
separately and congestion-window ramp included in the short burst. Report
requested and actual duration, boundary-censored responses and window overrun.
The runner must verify start/end BOOTTIME against the original grant and require
continuous read-only BPF authorization/health-map deadline coverage for accepted
timing samples. Denial counters and packet captures remain uncollected. Preserve
invalid samples and their causes; do not call a truncated grant a slow tunnel.

STANDARD includes the installed application's ingress/egress TCP proxies and two
JVMs. DUAL routes protected traffic through an inner gateway and independent
kernel gate, with an extra IPsec boundary, AA and supervisor. Preserve native
MTUs (STANDARD 1420, DUAL 1280, subject to actual observation). These are product
and topology differences, so an aggregate delta is not a pure cipher benchmark.

The currently qualified protected-resource contract is TCP. UDP goodput is
unsupported for a comparable authorized-resource test unless the inspected
product actually supports it; do not add UDP policy exceptions for benchmarks.

## Workload and evidence

Equivalent workload commands, executed inside the owning guest namespaces:

```sh
python3 /mnt/p24/workload.py serve --host RESOURCE_ADDRESS --port 8080
python3 /mnt/p24/workload.py goodput --host ACCESS_ADDRESS --port ACCESS_PORT \
  --seconds 0.5 --streams 1 --bytes 65536
python3 /mnt/p24/workload.py latency --host ACCESS_ADDRESS --port ACCESS_PORT \
  --seconds 0.5 --bytes 64
```

The client verifies echoed stream bytes and reports received payload Mbps counted
once, actual duration, per-stream bytes and setup times. Echo consumes both link
directions. Response latency is full application request/response RTT including
proxies/server, not TCP_INFO loopback RTT. Preserve individual observations and
report median, p95 and repetition spread with explicit units.

Collect guest total/process CPU, RSS, context switches, TCP retransmissions and
interface drops around each window. Record host/QEMU CPU and pressure separately.
Keep Python workload/server CPU separate from product processes; the single
selector client and verification may limit the measured rate. CPU flags alone
do not establish hardware-accelerated cipher use. Record actual
kernel, Java, strongSwan/WireGuard versions, resources and loaded unit limits.
Capture representative audit windows separately from timing aggregates so unequal
capture cost does not become a mode-dependent benchmark artifact; retain byte
counters for timed windows. Unexpected capture failures remain mandatory errors.

Use the existing encrypted peer-health ICMP path for transport RTT, DF size probes
and oversized-fragment tests. Distinguish that diagnostic path from protected
application delivery. Record actual MTUs, header sizes, fragmentation/reassembly
and PMTU outcomes without changing firewall policy. Time connect/startup,
rekeys, existing managed-gateway/runtime restart and fresh-authority recovery;
report explicit operator recovery separately from unattended recovery.

## Results — interrupted execution

Evidence retained privately at
`/home/wpotech/5gnexusguard-p24-20261107T035846Z/runtime-01/`:
`guest-evidence/samples.jsonl`, `matrix-result.json`, configuration, complete
command logs, rejected attempts, console log, host samples and preservation
snapshots. The writable guest disk is retained. No credentials are published.
The VM shut down with QEMU exit status 0; its backing image SHA-256 is unchanged.

The installed offline package check succeeded. Guest Linux was
`7.0.0-38-generic`, KVM host CPU model, 4 vCPUs and 4 GiB allocated RAM.
Root network namespace contained only loopback. No new dependencies were fetched.
Installed STANDARD units used the packaged runtime and JAR, service identity and
sandbox, with separate real node identities and guest-local discovery.
Native services used installed exporter, AA and supervisor units with dedicated
mTLS/test credentials and their original signed deadlines.

The final matrix produced 14 accepted windows and one rejected window, all in
repetition 0. Each throughput cell below has **n=1**, requested duration 0.5 s.
No between-repetition variability, confidence interval or sustained capacity is
established. Mbps counts verified echo payload received once; bidirectional
transport and Python echo/verification work are included.

| Workload | Unencrypted context Mbps | STANDARD Mbps | DUAL Mbps |
|---|---:|---:|---:|
| 1 stream, 4 KiB | 689.17 | 311.33 | 262.41 |
| 1 stream, 64 KiB | 4839.96 | 410.29 | 383.04 |
| 4 streams, 4 KiB | 1215.69 | 565.25 | rejected |
| 4 streams, 64 KiB | 6400.03 | 618.29 | not run |

STANDARD 64-byte responses: 833 completed requests in one window, median 0.462 ms, observed p95 1.925 ms.
STANDARD 4096-byte responses: 890 completed requests in one window, median 0.466 ms, observed p95 1.014 ms.

These are within-window distributions, not independent repetition estimates;
DUAL latency trials were not reached.

### Mandatory failure

The four-stream DUAL 4 KiB workload completed byte verification but failed
continuous health coverage. BOOTTIME values, in nanoseconds:

- Measurement: `1519075719842` through `1519586333482`.
- Original signed authorization deadline: `1520408165951` (not expired).
- Previous health check: `1519028136276`; deadline: `1519528136276`.
- Next health check: `1519572371097`, **44.235 ms after the old deadline**.
- The replacement was first observed by the read-only tracer at `1519583241783`.

The rejected window's raw 301.83 Mbps is retained for diagnosis and excluded from
accepted comparisons. It must not be interpreted as continuously authorized
throughput. This is a health-refresh/observation failure under load, not evidence
of a bypass or proof of a particular cipher bottleneck. Existing enforcement
was not weakened, deadlines were not extended and no product correction was
made without identifying the scheduling/health-path cause.

Earlier unbounded echo pilots also failed health coverage. The workload was
corrected to cap outstanding echo bytes at 128 KiB per stream identically for all
modes; a bounded single-stream pilot passed. The multi-stream failure above
persisted with that cap. Separate harness defects were corrected: transient
resource services are stopped before their namespace is removed; exited
namespace enumeration helper processes are skipped while both required charon
processes must still be found. Failed attempts remain separately retained.

Guest busy CPU during the final STANDARD throughput windows was 83.59–90.40%
of aggregate four-vCPU time; accepted DUAL throughput windows were 87.50–91.50%.
These single-window observations include workload, kernel and product work,
and cannot establish crypto-only cost. Raw process ticks, RSS, context switches,
guest memory/load and independently sampled host/QEMU CPU/load are retained.
Host and guest CPU percentages must not be combined or compared as equal units.

MTU/PMTU, fragmentation, repeated latency comparison, UDP, packet captures,
retransmission/drop counters and rekey/recovery qualification were not completed.
UDP protected-resource comparison is unsupported by this TCP-only authorization
contract; no exception was added. No performance target or regression conclusion
is inferred from this interrupted matrix.

### Cleanup and preservation

All benchmark namespaces were removed, BPF installed pins were absent, native
status reported `stopped=true`, `kernel_permitted=false`, `cleanup_errors=[]`,
and all STANDARD/native units were inactive before guest poweroff. All 24
pre-existing tracked target file fingerprints match the recovery reference.
No host network modification command was executed. Strict before/after host
network equality nevertheless returned false: an unrelated host veth interface
`veth2134d58` and its IPv6 routes disappeared during the run. The snapshots are
preserved; exact host equality is not claimed and that unrelated workload was
not modified to force equality.

Seven focused workload/map-coverage tests passed, including a regression built
from the observed four-stream deadline gap. Independent read-only review confirmed the 44,234,821 ns health gap, correct
rejection, CPU-unit arithmetic and exclusion of the rejected throughput. It
also identified native-only map-sampler CPU/GIL overhead as a comparison bias
for future accepted measurements. Full methodology acceptance remains BLOCKED.
No accepted milestone is committed or pushed while the
mandatory failure remains unresolved. Production security acceptance remains
BLOCKED; website readiness remains NO; installed P2 baseline remains WORKING.

### Recovery candidate

Five consecutive lookups still returned the old health entry after its deadline,
from `1519531439256` to `1519572792961`. The TC classifier rejects matching
packets at or beyond that deadline using BOOTTIME. The original signed grant
remained live. The 44.235 ms measures the time from expiry to the next check
timestamp. The next lookup that returned the replacement came 55.106 ms after
expiry. The actual publication time lies between the last stale observation and
the first replacement observation. The saved run lacks per-packet drop evidence
for this interval. Verified TCP echo can complete even when TCP retransmits.

The installed supervisor previously slept 80 ms after every tick and status
write, even when the tick had already exceeded the polling interval. Scheduling
the next poll relative to tick start removes that forced delay on overruns.
The original signed authorization deadline, health validation, 500 ms maximum
health window, and benchmark coverage requirement are unchanged. The saved
trace does not attribute the remaining cycle time to individual health commands
or to scheduler wait. The rebuilt package awaits focused four-stream validation.

Canonical remote verification: local HEAD and remote feature branch both equal
`a8ec0d02ab96cd89ae6874c5e4d6a47a1ae88664`. Benchmark tooling/report remain
uncommitted drafts because performance acceptance failed; no push was made.

### Focused recovery run — 2026-11-20 UTC

The approved 4-stream, 4 KiB TCP probe ran in a fresh NIC-free KVM overlay.
The native package SHA-256 was
`ff41862426e7e1f0ea278ebaccc29334059c7bdc56c7e6d6f5e8d8ab939cd835`.
Its installed supervisor matched the corrected source by SHA-256 before
execution. The probe failed the continuous kernel health coverage requirement.

| Event | CLOCK_BOOTTIME (ns) |
|---|---:|
| Old health check timestamp | 68047544187 |
| Measurement start | 68080354600 |
| Old kernel health deadline | 68547544187 |
| First observed expired entry | 68551133724 |
| Last observed expired entry | 68572204684 |
| Replacement check timestamp | 68572837067 |
| First observed replacement | 68582909866 |
| Measurement end | 68592369611 |
| Replacement health deadline | 69072837067 |
| Original signed authorization deadline | 69862650427 |

The observed check-to-check interval was 525.293 ms. The new check timestamp
was 25.293 ms past expiry. Three lookups returned the expired entry, and the
first replacement lookup came 35.366 ms after expiry. Publication is bounded
by the replacement check timestamp and the first lookup that returned it.
The authorization stayed live. The read-only SYN health-deadline counters
(keys 8 and 24) both stayed at zero. Those counters do not cover established
TCP traffic.

All four streams delivered verified echo payload, totaling 13,148,760 bytes
in 500.698 ms (210.087 Mbps). The sample is excluded from performance
qualification. Guest aggregate busy CPU was 90.15%, with 0% measured steal.
The supervisor accounted for 3.88% of one CPU and its waited-for children
38.81% of one CPU. The supervisor had 117 voluntary and 142 involuntary
context switches during the measurement. Its aggregate runnable wait
increased by 58.664 ms across the broader counter snapshots, which include
grant setup. The evidence does not attribute the overrun to a particular
command or run-queue delay. Removing the fixed sleep was insufficient under
this load.

The guest stopped with QEMU exit 0. BPF pins and guest namespaces were gone,
and the supervisor reported no cleanup errors. Host network configuration
and the backing disk matched their references. All 24 tracked target changes
were preserved. Private evidence is retained under
`/home/wpotech/5gnexusguard-p24-recovery-native-20261119T050029Z/focused/runtime-01/`.
The matrix and commit are gated on a passing focused probe.

### Single approved diagnostic run — 2026-11-20 UTC

The four-stream, 4 KiB sample passed the unchanged coverage check. The
installed supervisor and publisher matched the instrumented archive byte for
byte. Systemd rejected the diagnostic environment assignment because its name
began with a digit, so the supervisor ran with tracing disabled. The journal
records the rejection. The independent map trace, TCP result and counters are
valid. Per-stage, maximum cycle and wake-up timings are unavailable.

| Event | CLOCK_BOOTTIME (ns) |
|---|---:|
| First health check | 42428856220 |
| First independent observation | 42477202676 |
| Measurement start | 42480611640 |
| Replacement health check | 42828695389 |
| First independent replacement observation | 42860035460 |
| Previous health deadline | 42928856220 |
| Measurement end | 42992548704 |
| Replacement health deadline | 43328695389 |
| Original signed authorization deadline | 43760329030 |

The observed check-to-check interval was 399.839 ms. The independent sampler
saw the replacement 68.821 ms before the old deadline. All four streams
delivered verified echo payload, totaling 19,175,788 bytes in 500.129 ms
(306.733 Mbps). Guest busy CPU was 93.60% with zero measured steal. The
supervisor used 3.89% of one core and waited-for children accounted for 31.09%
of one core. The supervisor had 243 involuntary context switches during the
sample. The surrounding scheduling snapshots include setup and cannot identify
cycle wake-up delay. Both SYN health-deadline counters remained zero. These
counters do not cover established TCP segments.

The guest shut down normally with QEMU exit code 0. Host network configuration
and the backing disk matched their references. No guest namespaces, BPF pins
or supervisor cleanup errors remained. See
`/home/wpotech/5gnexusguard-p24-timing-20261120T125612Z/runtime-01/`
for private evidence, including the captured journal diagnostic.

The harness now checks the effective service environment before traffic and
requires the emitted timing file. The corrected diagnostic run awaits
separate runtime approval. This passing sample does not close the prior
intermittent renewal failure.

### Corrected traced run — 2026-11-20 UTC

The installed instrumented modules matched the rebuilt archive. The harness
verified the effective service environment, running process environment,
root-private writable trace directory, and active independent BPF sampler
before traffic. The guest emitted a root-owned 0600 trace with 22 completed
cycles. Two completed cycles overlapped the measured workload.

| Stage wall time (ms) | Longest overlapping cycle | Other overlapping cycle |
|---|---:|---:|
| Authorization validation | 1.872 | 7.774 |
| Tunnel verification, total | 414.801 | 216.724 |
| WireGuard route commands | 47.260 | 45.307 |
| WireGuard address commands | 37.453 | 54.650 |
| WireGuard echo command | 24.179 | 6.936 |
| strongSwan VICI commands | 241.199 | 81.225 |
| XFRM commands | 58.693 | 26.369 |
| BPF update and readback, total | 20.817 | 5.405 |
| BPF subprocesses within update/readback | 20.473 | 5.322 |
| Complete supervisor cycle | 453.135 | 246.583 |

VICI was the largest measured stage in the slow cycle, with the slowest
individual command taking 80.312 ms. Command wall time includes subprocess
launch, execution and scheduling. The trace cannot apportion time within VICI.
Actual cycle starts lagged their nominal 80 ms targets by up to 373.138 ms
because the preceding cycle was still executing. Once both the target time
and preceding cycle completion had passed, the largest start delay was
0.006252 ms across the overlapping cycle starts.

The workload ran from BOOTTIME 43086220261 to 43597470753 ns under an
original signed deadline of 44355994738 ns. The initial health deadline
was 43514076707 ns. The replacement was checked at 43446337536 ns and
independently observed at 43461248493 ns, leaving a conservative observed
renewal margin of 52.828 ms. Supervisor readback completed at 43467159198 ns.
The replacement deadline 43946337536 ns matched the independent map
sample. No expired entry was observed and the strict coverage check passed.

All four streams delivered verified data, totaling 15,091,916 bytes in
500.267 ms (241.342 Mbps). Guest busy CPU was 93.14% with zero measured
steal. The supervisor and its waited-for children accounted for 3.86% and
36.68% of one CPU respectively. The supervisor had 232 involuntary context
switches during the sample. Both SYN health-deadline rejection counters
were zero. The guest shut down with QEMU exit 0, no remaining BPF pins or
namespaces, no supervisor cleanup errors, and matching host network and
backing-disk snapshots. All 24 tracked target modifications were preserved.

The trace isolates the dominant stage in this passing run. The prior
intermittent expiry lacked a stage trace. The present evidence does not
justify changing the wake-up policy or claiming permanent coverage.
The full performance matrix was outside the single-run approval.

### Parallel verifier acceptance attempt — first window stopped

The guest verified the installed parallel-verifier package. The first
four-stream window started after grant readiness. The supervisor's final
cycle started at BOOTTIME 45667848281 ns. Authorization validation took
1.992 ms and the parallel health challenge took 470.972 ms. Its successful
result required the matching identities and SPIs and increasing counters.
The previous verified health deadline was 46151301735 ns. Publication began
at 46140877944 ns, and `bpftool map update` received a 10.392 ms timeout budget.
The subprocess call lasted 16.431 ms and timed out waiting for child exit.
There was no successful readback for this attempted publication. The
supervisor entered revocation and cleanup and exited with status 1.

The longest completed cycle in the retained trace was 242.678 ms. The final
cycle had no completion event and spent 473.030 ms before entering publication.
Process disappearance prevented the benchmark harness from saving its pending
sample and map trace. Because a subprocess timeout can occur after the write
and before child exit, the attempted map update's effect and any expired
interval are unknown. Subsequent windows did not run.

The guest stopped with QEMU exit 0. Post-failure cleanup confirmed no installed
pins or guest namespaces. Host network and backing disk snapshots matched.
Private evidence is under
`/home/wpotech/5gnexusguard-p24-parallel-20261120T175921Z/runtime-01/`.

The follow-up candidate replaces shell-based timed health publication with
an in-process BPF map update and byte-for-byte lookup. It checks the pinned
map ABI and remaining deadline before writing and reading. The harness now
retains partial traffic and map observations when a tracked process exits,
and attempts native stop even if signed revocation cannot complete. The
500 ms health window and signed authorization are unchanged. The follow-up
package and live packet behavior require a new isolated validation.

### Direct BPF publication — six accepted windows

The approved NIC-free VM installed the rebuilt archive (SHA-256
`f9178e8c70ba2fbbefd997d2b914bc3cdc391f5b7b2940c9d36933c6b4ed9ac7`).
The installed supervisor and publisher matched the build. All six windows
used four 4 KiB TCP streams and distinct signed Authorization V2 grants.
The unchanged continuous coverage rule passed in each window. Fourteen
completed health cycles overlapped the windows. Each showed three overlapping
health commands and completed the required before/after identity, SPI and
ESP counter checks before the publisher accepted its evidence.

| Window | Requested seconds | Verified echo Mbps | Guest busy CPU | Longest overlapping cycle (ms) | Longest direct BPF update and readback (ms) | Minimum observed renewal margin (ms) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 0.50 | 361.231 | 96.04% | 400.422 | 0.942 | 92.811 |
| 2 | 0.50 | 300.601 | 93.10% | 361.680 | 0.766 | 155.116 |
| 3 | 0.50 | 334.500 | 95.05% | 437.710 | 2.871 | 60.801 |
| 4 | 0.50 | 390.915 | 97.55% | 416.025 | 1.096 | 79.473 |
| 5 | 0.50 | 333.380 | 95.57% | 430.083 | 1.711 | 56.748 |
| 6 | 1.25 | 348.499 | 94.39% | 386.966 | 1.226 | 109.254 |

There were zero sampled expirations. The two SYN health-deadline counters
remained zero across the suite. The longest cycle spent 420.834 ms in
parallel tunnel validation. Its four VICI subprocesses took 385.370 ms
combined and VICI was the last worker to finish each snapshot. The separate
stage sums overlap and do not add to wall time. The maximum wake delay after
both the scheduled target and the preceding cycle end was 5.567 microseconds
among overlapping cycle starts.

QEMU returned 0. Supervisor cleanup reported no errors, the guest had no
remaining test namespaces or BPF pins, and the backing disk hash matched.
Strict host-network equality failed. The snapshot differences were confined
to one added host veth on an existing container bridge and its associated
IPv6 routes. The QEMU command used `-nic none`; the runner issued no host
network changes. All 24 tracked target modifications were preserved.

A total of 140 focused unprivileged tests passed. Positive windows do not
exercise unauthorized traffic, crash, stale evidence, or revocation packet
denial. Those live regressions and an independent security review remain
pending. These short measurements establish observed coverage for the six
grants. They do not qualify sustained reliability or the full performance matrix.
Raw traces and map samples remain in the private direct-map runtime evidence.
