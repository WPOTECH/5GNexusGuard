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
