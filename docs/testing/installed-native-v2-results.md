# Installed Native Dual-Tunnel Access integration

Baseline: `40c0941`, branch `feat/native-dual-tunnel-access`, 5GNexusGuard.
Production admission remains disabled. STANDARD, P0/P1 and prior package evidence
remain preserved. An installed signing component is not packet acceptance.

## Live Java issuance slice

`NativePolicyExporter` has an optional private V2 input directory, enabled only
in NATIVE_DUAL/NATIVE with explicit separate operator/supervisor public pins.
Properties: `mesh.native.v2.directory`, `mesh.native.v2.operator-key`,
`mesh.native.v2.supervisor-key`, plus the existing service/client scope properties.
Omitting configuration leaves this component dormant. The legacy periodic lease
export remains deny-only; no ledger state is automatically converted into approval.

The local trusted operator publishes owner-owned 0600 `approval.json` containing
only an exact payload and external operator signature, in an owned 0700 directory
with protected ancestors. The component reads the current supervisor-signed
`challenge.json`, verifies boot/session/nonce/scope and pinned signatures through
the existing V2 issuance primitive, and countersigns with the live persisted
`NodeIdentity`. Local CLOCK_BOOTTIME comes from a fixed isolated Python clock
helper, never request data. The original signed deadline is preserved. The output
is atomically published as `inbox.json` for the receiver. No operator secret,
test signer, synthetic grant helper or HTTP signing endpoint is installed.

Private inputs are bounded, non-followed, regular, single-link, owner-owned and
0600; duplicate JSON is rejected. Same-UID writers remain trusted. In-memory
deduplication is not durable replay protection: receiver session, journal and
high-water enforcement remain authoritative. Crash loss of an unacknowledged
publication fails closed; this is not a transactional approval-delivery claim.

Five focused Java regressions cover actual persisted identity countersigning,
exact deadline retention, forged approval, expiry, wrong current challenge nonce,
duplicate fields and unsafe inputs. All 48 Java tests pass in private scratch
`/home/wpotech/5gnexusguard-installed-v2-d22tsfbh`; successful package augmentation
also exercised scheduler/configuration validation. The duration expression was
corrected after augmentation rejected the initial non-ISO spelling.

An actual installed Quarkus JAR/systemd exporter produced the envelope in
`/home/wpotech/5gnexusguard-p2-installed-dual-20261101-06`. Independent read-only
review verifies the external operator signature and live node countersignature,
byte-for-byte approved payload preservation, unchanged 40,471,421,609 ns BOOTTIME
deadline and 2.501-second original lifetime. Receiver history records
PENDING_FRESH_APPROVAL → AUTHORIZED, then expiry. Kernel permission stayed false.
The overall run remains FAIL pending AA/health/kernel integration; no protected
TCP pass is claimed by this slice.

Independent scoped component review is PASS with no introduced HIGH/CRITICAL
finding. The original pre-acceptance supervisor challenge/public provisioning
record was not retained by that run, so its original supervisor signature cannot
be independently reconstructed from the rotated saved challenge. Source review
and negative tests cover that check; later full acceptance must retain the
complete provisioning/challenge chain. No production or website acceptance
follows from this component milestone.

## Installed services and protected traffic acceptance

Executed 2026-11-02 UTC in the existing product's disposable package-VM lineage,
using fresh overlays only. The original installation-failure disk, its evidence,
the stopped package baseline and all prior P0/P1 evidence remain intact.

The optional add-on installs disabled AA/exporter/supervisor units and the existing
kernel gate object. It never installs the development Fixture/JavaIssuer/packet
experiment as a product service. The installed entrypoint requires an explicit
private DISPOSABLE_VM profile, pinned actual boot UUID, KVM/QEMU, root and no root
network adapter other than lo. Production admission=true is rejected. Mandatory
operator credentials are passed to the native topology; the original operator
entrypoint remains deny-only and STANDARD's service/capabilities are unchanged.

Actual component inventory and reproduction contract:
`packaging/linux/NATIVE-ISOLATED.md`. The live application is the packaged Quarkus
JAR, and its node mTLS key is enrolled against its actual persisted Ed25519
identity. The external test operator signs explicit fresh approvals; neither the
installed exporter nor supervisor holds an approval-signing API/private-key
configuration. AA and supervisor state persist privately and start denied or
quarantined as required. Node signing, AA attestation, independently checked tunnel
health and original BOOTTIME deadlines all precede map publication.

### Demonstrated failures and narrow corrections

* Quarkus augmentation rejected the first scheduler duration spelling; the
  accepted ISO duration is PT0.1S. No deployment accepted the failed build.
* New table-name validation initially rejected the unchanged default's digit 2;
  the literal-identifier validator was corrected and existing regressions passed.
* Installed charon was denied its private transport strongswan.conf by AppArmor.
  The add-on now appends narrow local includes while preserving operator policy,
  and permits only transport-role config/VICI and one-level swanctl PKI paths.
  Profiles remain enforced; there is no profile disable or capability expansion.
* The first observer used /root, hidden inside the service's protected mount
  namespace. Observer evidence moved to a root-private /var/lib path. Namespace
  access uses the owned supervisor's mount namespace rather than weakening unit
  isolation or faking a container marker.
* Generated test PKI lacked extensions required by strict TLS verification.
  AKI/SKI/key-usage were corrected in the external test operator; TLS verification
  was never relaxed.
* The test operator initially attempted restart recovery against a genuinely new,
  unquarantined AA. Its exact 409 rejection is now a negative control, followed
  by explicit initial authorization. Real AA restart still requires recovery
  and a newer authorization/epoch.
* The installed strongSwan 6 reports selectors as [udp/51821], whereas health
  expected [17/51821]. Health now normalizes only anchored local/remote lines for
  the exact two /32 UDP/51821 selectors. IPs, prefixes, port, peer SPIs, CHILD_SA,
  echo and ESP progress checks remain unchanged. The named-form regression failed
  first, then both spellings passed; wrong protocol/port remain denied.

The earlier timed-out grant runs remain FAIL. Run 07's verified AA highwater
(generation 2/revocation 0/epoch 2) and saved live SAs established the actual
selector-format dependency; no permit check was removed to force traffic.

### Complete accepted run 08

Private evidence:
`/home/wpotech/5gnexusguard-p2-installed-dual-20261101-08`.
Both guest and original runner results are PASS. Installed local base and add-on
archives matched all recorded hashes and dependencies were installed offline.
The tested base archive is
`/home/wpotech/5gnexusguard-installed-native-base-03/defenderlink-mesh_1.0.0+p2.git40c0941_amd64.deb`,
SHA-256 `ae3153652c548e8c9e55355b65d3838e33fa735e6767270295e19af19491602f`;
it contains the reviewed live-signing working-tree changes subsequently committed
at c7b946c plus the native CLI. The tested add-on is
`/home/wpotech/5gnexusguard-native-addon-05/defenderlink-native-prototype_1.0.0+p2.gitc7b946c_amd64.deb`,
SHA-256 `df1c691e75e90885ff8f14e65b3c504883d3568e46e188487267abbb489f3c37`.
Package version labels identify the build baseline; these hashes identify the
exact tested working-tree artifacts. No release or main-branch publication occurred.

Independent review PASS, no introduced HIGH/CRITICAL finding:

* Original supervisor challenges verify with the retained configured pin; live
  Java signatures verify against the persisted node identity and external
  operator pin. The mTLS node certificate has that same public key. No test
  signer or node-key substitution supplied the service envelope.
* Grants at native generations 2 and 5 retain their approved absolute deadlines
  36,685,453,144 and 44,685,078,582 ns BOOTTIME. The original lifetimes are 2.501 s.
  Kernel authorization and health epochs match; heartbeat is no later than
  checked+500 ms or the original approved/AA deadline.
* Fourteen captures finalize cleanly with zero drops. Initial public directional
  egress has 21/12 ESP packets; transit has 33 WireGuard type-4 packets plus the
  tagged direct-underlay SYN. Recovery has 9/6 ESP and 15 WG transport packets.
  Protected SYN identities match all four plaintext boundaries (two initial,
  one recovery). Authorized payload reaches the resource and both WG interfaces,
  and is absent from public/transit captures.
* Initial kernel permits are zero and actual protected TCP is denied. After
  authenticated grant, real persistent and new TCP sockets echo through the
  installed transport. A tagged valid-tuple plaintext underlay SYN is captured
  at transit, increments the inner nft DROP counter 0→1, and is absent at inner
  WG/resource boundaries. Authorized TCP still succeeds after that probe.
* Signed REVOKE clears authorization and health maps. Established and new TCP
  attempts are denied before the original grant expires. TC program identities
  and both exact nft interlocks remain unchanged across grant and revocation.
* `5gnexus native-status` reports the installed publisher observation. All units
  stop through the CLI; a retained TCP socket also fails after service stop.
  Named namespaces/pins disappear. Restart remains denied until fresh AA recovery,
  newer AA policy and separately signed native recovery/approval. Real protected
  TCP then succeeds again, followed by clean controlled shutdown.
* The owned QEMU exits 0; normalized host configuration matches and its baseline
  disk hash is unchanged. Existing VMs were not operated. Raw lifetime-countdown
  differences are not labeled byte-identical snapshots.

### Tracked reproducibility runner and separate host audit

`scripts/operational/run_installed_dual_vm.py` prepares a fresh overlay/read-only
seed with only local verified archives. `installed_dual_operator.py` is an
external test operator and packet observer, not the product runtime. The observer
checks KVM, lo-only root networking, the mounted seed and instance metadata before
mutation; the runner establishes the seed's read-only mount. It provisions test
credentials, then exercises actual installed units without importing the old
packet experiment or signing fixture.

A real replay through those tracked scripts in
`/home/wpotech/5gnexusguard-p2-installed-dual-repro-20261101-01` repeats all 86 guest
checks PASS, including crypto/control flow, protected TCP, denial, 14 clean
captures and recovery. Independent read-only review confirms that guest PASS.

**Its strict overall runner result is FAIL and stays FAIL.** The host snapshot
shows vethc7e3b18 replaced by vethf456c58 on existing br-cd39b3537dba, with three
IPv6 routes removed and two added on those devices. No actor/event attribution
was recovered; do not call this a corroborated Docker event. Boot ID, existing
VM list, host rules and other configuration match. The reviewed invocation uses
-nic none and no host network write, and the source baseline disk is unchanged;
these facts do not relabel the snapshot difference as equality. No passed packet
case was rerun solely to replace this host-audit result. Run 08's complete accepted
PASS and the replay's guest PASS/strict host FAIL are separate evidence.

Final relevant checks: 48 Java tests; 294 native Python tests (14 existing skips);
11 packaging regressions; 4 operational acceptance regressions; shell syntax,
systemd verification and git diff --check pass. Java/build outputs remain in
private scratch. The 24 original target/ paths retain their fingerprints.

The installed guarded prototype is functionally WORKING for this fixed IPv4
scope. P0/P1 and STANDARD baselines are preserved. Production security acceptance
remains BLOCKED: this co-located test operator/AA/root-service deployment does not
establish independent key custody, whole-store rollback resistance, general
external-gateway/IPv6/performance acceptance or comprehensive installed crash
reconciliation. Website readiness remains NO. No public website, Cloudflare,
pfSense or main-branch changes were made.
