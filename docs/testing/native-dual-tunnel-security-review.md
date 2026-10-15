# Bounded IPsec readiness extension — 2026-10-15

Status: **NOT production accepted**. The independent implementation pass initially
ran unprivileged regressions only. Subsequently the isolated, parent-approved
Docker packet harness ran (`readiness-1`, `-2`, `-4`, and `-5` failed during
capture/restart assertion development; `ipsec-dual-readiness-3` and `-6` exited 0). No host-network or `neural0`
operation was performed. See `native-dual-tunnel-results.md` for the later packet
evidence and remaining failures. Experimental WireGuard and website files were not
modified.

## Supervisor review and fixes

Line citations below refer to the revised source; the preceding behavior was
reviewed directly from the workspace, without modifying Git state.

| Finding | Consequence and minimal change | Regression coverage |
| --- | --- | --- |
| HIGH: lease duration was sampled before slow route and VICI checks | Checks could consume the remaining lifetime, then install a fresh relative nft timeout using the stale duration. [native.py:328](../../scripts/ipsec-dual/native.py#L328) now reads the lease and samples time after health checks; unready or invalid leases install no authorization. | Expired deadline after read; unready path does not read or authorize a lease. |
| HIGH availability, with stale readiness risk: dead charon was never restarted; only CHILD_SA initiation was retried | SIGKILL can leave kernel SAs behind and the other endpoint can still report an established SA. [native.py:213](../../scripts/ipsec-dual/native.py#L213) requires both daemon processes alive and matching endpoint/gateway IKE SA SPIs, selectors and reqid. [native.py:282](../../scripts/ipsec-dual/native.py#L282) revokes authorization before restart, forces teardown of a surviving peer's stale SA, and withholds authorization if teardown fails. It never flushes XFRM globally or regenerates credentials. | Dead gateway cannot reuse surviving endpoint status; mismatched peers rejected; revoke-before-restart; surviving teardown errors fail closed; 28 Python regressions and `ipsec-dual-readiness-7` exited 0. |
| Recovery defect: any existing route was accepted, including a wrong fallback route | [native.py:195](../../scripts/ipsec-dual/native.py#L195) replaces only five owned /32 routes with their exact next hops/source/device. This is an availability/correctness fix; existing ACLs already deny public plaintext fallback. | Wrong existing routes replaced; command errors report not ready. |
| Diagnostic disclosure risk: command exceptions included swanctl/WG output; timeout exceptions could include command arguments | [native.py:18](../../scripts/ipsec-dual/native.py#L18) suppresses both output and arguments, including timeout exceptions. The integration top-level error no longer prints a traceback. No exploit or actual key disclosure is asserted. | Secret sentinel absent from failure and timeout errors. |

A second read-only review found a MEDIUM false-readiness case: an unrelated
CHILD_SA could supply the expected selectors while `inner-transport` had the
wrong port. A failing regression reproduced it; readiness now binds name,
reqid and both selectors to the same CHILD_SA section on each peer, then
compares matching IKE SPIs. The current isolated run passed after this change.

Restart in [native.py:240](../../scripts/ipsec-dual/native.py#L240) refuses a live
process, removes only the owned private VICI socket, reloads existing credentials,
and waits for successful VICI configuration loading. Five attempts, each with the
existing ten-second command timeout, bound each start attempt; a live unloaded
process is killed and reaped. Recovery is retried by the existing supervisor loop.
This is an availability mechanism, not certificate renewal or an external daemon
manager. Full-product crash/restart data-plane interoperability remains unvalidated;
`ipsec-dual-readiness-7` did exercise isolated crash/restart traffic.

Selectors remain exactly `10.77.0.1/32[17/51821]` and
`10.78.0.2/32[17/51821]`, reqid 42, tunnel ESP. No accepted address, port, forwarding
rule, or established-flow bypass was added. Accept counters were added to existing
rules for observations; chain defaults remain drop.

## Evidence design

Every fault case uses a fresh successful authorized echo baseline. Five
bidirectional captures observe endpoint public, outer gateway public, outer
transit, inner gateway ingress/transit, and resource. Each has baseline, fault,
and recovery files; an overlapping continuous capture spans the gaps between
phase setup/teardown. Capture startup requires tcpdump's listening acknowledgement.
Successful validation requires normal capture exit and exactly zero kernel drops.
Empty files cannot prove successful transport: positive phases require encrypted
packets at all four transport boundaries and the synthetic marker at the resource.
Denied transport-fault phases require the marker to be absent from the resource.
Seven per-phase captures include separate `tcpdump -Q out` wire-egress views on
both public interfaces. Linux AF_PACKET receive captures can include decrypted
post-XFRM traffic: the all-direction public files are diagnostic and must not be
interpreted alone as physical-wire plaintext escape. Public wire-egress assertions
require only ESP/IKE; transit IPv4 permits only inner UDP/51821. Neither transport
boundary may contain the application marker.

Each phase records before/after `swanctl --list-sas`, `ip -s xfrm policy`, owned
namespace routes and nft rules/counters. Dead daemons are recorded as exited,
not as zero SA counters. These are raw observations for comparison, not fabricated
counter deltas or proof that a particular drop rule caused every denial. Other
observation failures fail the run. No `ip xfrm state`, WG private-key dump,
credential copy, payload print, or private daemon-log export is used. Resource
pcaps intentionally contain synthetic test plaintext; logs do not print payloads.
Artifacts are written directly under `/evidence/faults`, including on failure.
An exception before validation leaves incomplete artifacts, never a passing phase.

The harness refreshes its synthetic three-second lease after slow observations
and fault injection, immediately before transport-denial probes. This avoids
mistaking expiry during setup for successful fail-closed behavior. Revocation,
lease-expiry and crash-gate cases deliberately do not refresh after their action.
They assert their own denial and retain the same phase observations/captures.
Recovery allows eight attempts, with bounded subprocess timeouts. Missing routes
withhold authorization. There is no unbounded retry loop in a fault case.

Implemented cases (subsequently exercised by the isolated
`ipsec-dual-readiness-3` packet run; not a full-product acceptance test):

- Outer public link and inner WG link down/up, including exact route repair.
- Named SA removal/recovery.
- Outer and endpoint owned charon SIGKILL/restart. SIGKILL is limited to the
  tracked lab child process. Denial is explicitly after supervisor-style
  detection/revocation; daemon death alone is not claimed to stop kernel ESP.
- In-flight traffic launch versus revocation; deterministic established-flow
  revocation; kernel authorization expiry and subsequent recovery.
- Live wrong-port/public/outer-origin bypass probes; wrong pinned certificate
  identity; wrong WG peer; injected endpoint fallback route and restoration.

## BLOCKED / unresolved acceptance work

- **DNS failure:** the supplied profile uses literal public addresses and numeric
  WG endpoints; DNS SAN identities are authentication names, not resolution
  dependencies. Adding DNS allowance would change the fail-closed ACL contract.
  An artificial resolver outage here would produce a vacuous result. A real
  hostname-dependent deployment and isolated resolver fixture are required.
- **Runtime certificate expiration:** lease expiry and wrong identity are not
  certificate-expiration tests. Lab certificates last two days, and their signing
  key is deleted after issuance. There is no approved short-lived PKI/time fixture
  or defined production expiration policy. Do not change host time. Required
  follow-up: establish while valid, cross notAfter, observe existing-session
  behavior, force reauthentication and a fresh negotiation with expired material,
  require denial, then install valid replacement material and recover. Offline
  `openssl verify` or a mocked date would not establish runtime behavior.
- **Full races:** the in-flight test does not prove simultaneous exporter refresh,
  revocation, rekey and restart. Scheduling may let the first flow complete before
  revocation. It asserts only post-revocation denial. A running product exporter /
  supervisor fixture and synchronization barriers are required for stronger claims.
- **Crash recovery:** the isolated `readiness-3` run exercised both owned charon
  SIGKILL/restart paths with seven per-phase captures and recovery traffic. It
  does not prove an unbounded production lifecycle, rekey race or external
  gateway recovery. No XFRM flush or widened ACL fallback was introduced.
- **HIGH — supervisor timing / absolute lease deadline:** nft timeout is relative to transaction application; process
  scheduling / command delay after reading the lease can still overrun the absolute
  deadline. The fixed stale pre-health-check duration is not a hard real-time
  guarantee. Existing three-second kernel expiry bounds an already-installed lease
  while a supervisor is stalled. Atomic lease replacement versus renewal remains
  part of the product integration race gap.
- **HIGH — daemon-death detection window:** kernel SAs can remain active after
  SIGKILL. The crash fixture explicitly calls `authorize(0)` before its denial
  assertion; it does not show whether a flow succeeds between death and supervisor
  detection/revocation. The timed nft element bounds an already-installed lease,
  but this window needs a running supervisor and deterministic traffic barrier.
- **Underlay capture scope:** outbound IPv4 is checked against pinned peer IPs
  and ESP/IKE ports, and IPv6 egress is rejected. ARP and non-IP Ethernet frames
  are not treated as plaintext application data; this finite pcap interval is
  not a general guarantee about every host packet or deployment.
- No performance, external gateway/pfSense, NAT-T, revocation PKI, or full product
  exporter/supervisor deployment acceptance is claimed. Marker absence only speaks
  to the captured synthetic traffic, not all possible plaintext or host compromise.

## Unprivileged validation executed

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/ipsec-dual -p 'test_*.py' -v
```

25 tests passed, including existing profile/credential tests and new mocked
supervisor/capture regressions. Mocked process/netns calls do not prove real packet
behavior. Python source compilation was also checked in memory (no bytecode output)
for `integration.py`, `native.py`, and `test_native.py`. No production PASS is asserted.
Subsequent independent findings led to two more regressions: mismatched gateway
IKE SA and a failed surviving-peer teardown. The current suite runs 28 tests;
`ipsec-dual-readiness-7` executed the revised packet checks (976 PASS lines).
The HIGH absolute-deadline and crash-detection windows above remain open.
