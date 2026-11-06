# Installed pfSense interoperability — P2.3

Baseline `7c09ad7`, `feat/native-dual-tunnel-access`, canonical
`WPOTECH/5GNexusGuard`. Evidence is private and local under
`/home/wpotech/5gnexusguard-p23-20261106T034901Z`. This qualification is the fixed
IPv4 test-resource prototype, not production security acceptance.

## Preservation and real deployment

The operator staged an independent copy of the stopped original `pfsense`
domain's disk. Its supplied SHA-256 and the independently verified staged hash
are `bb9b2bfc0762dfc9180d3d127a143235542f32ee0993f490160490196df36fb7`.
The original domain/disk were never started or used as writable QEMU inputs.
The staged base is read-only backing for a disposable overlay. The corrected
pfSense deployment uses a further writable child of the preserved first overlay;
`pfsense08-backing.local.json` records the complete chain. The Linux guest also
uses a fresh overlay of the retained installation baseline. No existing libvirt
domain or network was modified.

Real pfSense CE 2.7.2 / FreeBSD 14.0-CURRENT / strongSwan 5.9.11 boots from that
copy. Its unique disposable UUID and test virtio MACs are recorded in QEMU
invocations. Two private Unix-socket links join its WAN/transit NICs to the
installed Linux endpoint/inner gateway. There is no TAP, host bridge, NAT or
physical-network connection. The installed supervisor moves only the two pinned
guest NICs into its owned namespaces. The resource is a real TCP echo process
inside the protected resource namespace.

The installed base/add-on supply Java's actual persisted signer, mTLS AA,
supervisor, strongSwan client, WireGuard peers, TC programs and nftables gates.
Services start through `5gnexus native-start`/systemd. No development packet
harness supplies their tunnel, issuer, authorization or enforcement. A separate
external test operator provides test credentials and independently signed V2
approvals and observes packets. pfSense receives its outer test identity and CA
only, never a WireGuard private key or application-authorization signing key.

## Minimal changes and retained failures

`external_gateway.py` substitutes guest NIC links and a real external responder
for the managed outer Linux gateway. The old native topology and default guard
remain unchanged. Endpoint-only credential provisioning is explicit; the old
default still provisions reciprocal endpoint/gateway credentials. External health
checks the owned local process, exact selected CHILD selectors, directional
VICI/XFRM SPI binding and bidirectional ESP progress around a fresh inner WG echo.
No appliance clock/process report is trusted as an admission authority. V2,
immutable deadlines, TC bytecode and nftables enforcement remain unchanged.

Every failed run remains failed in its original files:

- Offline Linux boot initially waited for DHCP. The disposable seed was corrected
  to use optional, non-DHCP test NICs. The failed boot overlay is preserved.
- Checkpoint 01 stopped when the observer omitted the private AA state directory.
  Restoring that existing provisioning step fixed the runner; the installed AA
  correctly refused to start without its directory.
- Checkpoint 02 delivered authorized TCP and enforced disconnect, then failed its
  audit because a bidirectional Linux interface capture included post-XFRM
  decapsulation. Directional endpoint egress plus authoritative bidirectional
  QEMU link captures corrected the observation point; the FAIL was not relabeled.
- Checkpoint 03 passed traffic, underlay denial and both rekeys, then AA rejected
  an observer revocation counter of zero with 409 `nonmonotonic revocation`.
  The operator now increments the counter; no AA check was relaxed.
- Checkpoints 04/06 exceeded a short original grant during combined diagnostics
  and disconnect checks. Separate explicit signed approvals now isolate those
  operations. No issuance deadline was extended. Checkpoint 04 also retained an
  unclassified map-revoke cleanup error.
- Checkpoint 05 recovered IPsec after a real pfSense reboot but rejected RECOVER
  directly from expired native state. The observer now sends the required signed
  REVOKE, RECOVER and fresh approval. Native admission was not changed.
- Checkpoint 07's 82 guest checks passed, but independent physical-wire audit
  correctly failed the overall run: **67 clear reverse-direction WG packets**
  appeared on WAN (57 keepalive-size transports, 10 handshakes). No protected
  application payload was observed there. This was a real outer-transport
  fail-closed gap, not an ingress capture artifact.
- Checkpoint 08 verified the narrow appliance correction: authoritative WAN had
  **273 ESP, 48 IKE and zero clear WG packets**, and LAN had 353 WG packets.
  Protected traffic and gateway recovery passed. Its overall result remains
  FAIL: focused stop cycle 1 reproduced a health-map-clear helper receiving
  SIGTERM (`exit=-15`). That exact diagnosis motivated the shutdown-order fix.

### Appliance correction

Existing floating WG pass states could bypass an outbound rule after IPsec
policies disappeared. The test-copy-only script
`scripts/operational/pfsense_deny_wg_fallback.php` installs four exact quick
stateless passes: each peer direction on both transit and enc0, with both UDP
ports 51821. A separate quick WAN egress block denies the reverse clear tuple.
The later quick no-state rules supersede pfSense's earlier nonquick enc0
keep-state rule. IKE/ESP stays stateful. Only stale test-peer-pair states are
cleared; there is no global state-policy change or pfSense source patch.

The script checks the independently recorded disposable UUID, version and test
NIC MACs before loading configuration, then checks the P23 interface profile
before mutation. A wrong-UUID negative exited 255 and retained the identical
configuration SHA. Actual loaded rules and live state snapshots are retained.
During protected TCP the snapshot contains IKE/ESP states and no WG states.
After reboot the WAN deny counter recorded 44 dropped fallback packets in
checkpoint 08, with zero corresponding WG frames on the authoritative WAN.

### Installed shutdown correction

The native supervisor unit now uses `KillMode=mixed`, with explicit final SIGKILL
and the unchanged 30-second timeout. SIGTERM reaches the main supervisor first,
allowing both mandatory zero/readbacks and owned transport cleanup before helpers
are terminated. Remaining cgroup processes are killed when the main process
exits or the timeout expires. Capabilities, AA/exporter units and kernel deadline
semantics do not change. Revocation errors remain fatal and retain bounded,
allowlisted diagnostic types/reasons/exit codes; arbitrary exception text is not
exported. Focused regression tests verify both map-clear attempts, retained
uncertainty and exclusion of raw private text.

## Final acceptance

**Checkpoint 09: PASS**, including independent review and final preservation
checks. `qualification-09.local.json` records the strict combined result.
The installed base archive SHA-256 is
`ae3153652c548e8c9e55355b65d3838e33fa735e6767270295e19af19491602f`;
the exercised native add-on SHA-256 is
`3a58549e7e70de98d7364299219cc86ae55a6fc841615ae9bc196dbe8795451a`.
These archives were built from the feature worktree at the baseline before this
milestone commit. Reviewed runtime/module/unit bytes match the installed archive.

The final guest reports 88 passing checks. Actual protected TCP works initially,
after both rekeys, and after a real pfSense reboot with new authority. Pregrant
and unauthorized-port attempts are denied. An assigned-source plaintext TCP SYN
sent by pfSense appears at transit, increments the inner DROP counter by one,
and is absent at all protected boundaries. Authorized TCP still works afterward.
Signed disconnect blocks established and new TCP before its original deadline;
final maps are zero and retained sockets cannot forward after service stop.

All five original signed grant lifetimes remain 2.501 seconds:

| Native generation | Original absolute BOOTTIME deadline (ns) |
| --- | --- |
| 2 | 95,090,763,309 |
| 5 | 96,494,337,572 |
| 8 | 98,649,517,102 |
| 11 | 105,518,272,291 |
| 14 | 202,766,738,641 |

The kernel authorization deadline matches the original signed deadline; health
remains independently bounded. The outage passes the original generation-11
expiry with zero authorization/health maps. AA revocation then increments its
own counter. After gateway recovery, tunnels alone cannot restore admission.
New AA authorization and signed native REVOKE/RECOVER/new approval are required
before protected TCP succeeds again. This is not a new active-AA-revocation
qualification: that particular AA revocation occurred after native expiry.

CHILD rekey changes both directional SPIs; IKE rekey changes the IKE pair. New
session/SPIs after the gateway reboot and both inner WG handshakes are retained.
The recovery uses explicit initiation through the installed client's swanctl;
unattended appliance recovery is not claimed.

The authoritative bidirectional WAN capture has **369 frames: 273 ESP, 55 IKE,
zero UDP/51821, zero clear WG and no protected application marker**. Remaining
frames are separately classified bootstrap/DHCP/NTP/IPv6 traffic. LAN has 405
frames, including 362 WG packets and the intentional negative probe. The final
WAN fallback-deny counter is 51 packets / 3,988 bytes with zero state creations.
Live PF state inspection during authorized TCP retains IKE/ESP states and no WG
states. This proves the correction blocks attempted fallback rather than simply
removing the inner transport.

All eight pcaps end on complete, untruncated records; all six Linux tcpdump logs
report zero drops. QMP object-del receipts prove both wire captures finalized.
Independent review matches 19 protected SYN identities across all four plaintext
boundaries and corroborates the physical negative probe's absence there.

The reviewer verifies retained supervisor challenge signatures, final operator
approval/revocation, node TLS owner identity/pins, exact package/source bytes,
map transitions and stable TC program identities. Earlier node envelopes are
overwritten by later operations; live Java/receiver assertions establish that
path, and are not described as a complete offline signature archive.

Three additional installed supervisor start/stop cycles each remain denied,
finish with systemd Result=success, empty cleanup_errors and zero surviving
cgroup helper processes. Final owned namespaces and pins are absent. The earlier
SIGTERM/readback failures are not waived; the corrected unit is exercised by
these focused lifecycle regressions.

Final preservation audit: both disposable QEMU guests stopped, the staged base
hash still matches, the original libvirt domain remains shut off, normalized
host configuration matches the initial snapshot, and all 24 pre-existing target/
path fingerprints match. No original pfSense, Polaris networking, other libvirt
VM, website, Cloudflare or main-branch changes were made.

Focused checks pass: 5 Java NativeV2Inbox tests; 5 external-adapter, 38 publisher,
30 AA, 4 credential/profile and 12 packaging tests (the packaging suite also ran
as root with no network and all capabilities dropped). Shell syntax, systemd
unit verification and git diff --check pass. P0/P1 and STANDARD protocol behavior
were not rerun or altered. Independent scoped security review reports PASS and
no introduced HIGH/CRITICAL finding.

P2.3 interoperability and the installed prototype are WORKING for this tested
IPv4/policy-based pfSense profile. Production security acceptance remains
BLOCKED and website readiness remains NO. No comparable STANDARD/DUAL_TUNNEL
performance measurements are claimed by this packet qualification.
