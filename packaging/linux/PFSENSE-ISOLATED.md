# Installed pfSense interoperability profile

This is an explicitly provisioned disposable-VM profile for the installed native
prototype. STANDARD remains the default and production admission remains denied.
Use a stopped, independently staged pfSense disk and a new writable overlay.
Never boot the original domain or use its disk as a writable QEMU drive.

## Qualified topology and configuration

The Linux VM contains the actual installed Java exporter, Authorization Authority,
native supervisor, strongSwan client, WireGuard peers, TC programs and nftables
interlocks. Its endpoint, inner gateway and resource occupy owned network
namespaces. The outer gateway is a separate real pfSense installation. Both guest
NICs use private QEMU Unix socket links, with no host bridge, TAP, NAT or physical
interface. The outer gateway holds its dedicated IPsec test identity only; it
receives no WireGuard private keys or application-authorization credentials.

| Boundary | Linux address | pfSense address |
| --- | --- | --- |
| Untrusted outer link | endpoint `192.0.2.1/30` | WAN `192.0.2.2/30` |
| Inner WG transport link | inner gateway `10.78.0.2/30` | transit `10.78.0.1/30` |

The endpoint transport source is `10.77.0.1/32`, with WireGuard UDP/51821 at both
ends. Inner WG addresses are `10.79.0.1/32` and `10.79.0.2/32`; the protected test
resource is TCP `10.80.0.2:8080`. These addresses remain inside the disposable
guests even when similarly numbered host routes exist.

The exercised appliance is pfSense CE 2.7.2, FreeBSD 14.0-CURRENT and strongSwan
5.9.11. Policy-based IPsec preserves the installed client's existing narrow
selector contract; route-based interoperability is not qualified by this test.

Provision a dedicated CA and reciprocal `endpoint.test`/`gateway.test` DNS SAN
certificates. The pfSense phase 1 uses IKEv2, certificate authentication, these
exact peer identities, AES-256-GCM with 128-bit tag, PRF SHA-384 and ECP-384.
Phase 2 is tunnel ESP, AES-256-GCM with 128-bit tag and ECP-384 for rekey. pfSense
configures host selectors `10.78.0.2/32` and `10.77.0.1/32`; the client's request
narrows the actually negotiated selectors to UDP/51821 on both hosts. Verify the
negotiated result on both peers. Do not accept an IKE_SA alone as traffic proof.

On the disposable appliance, allow only the exact peer IKE/ESP outer traffic and
UDP/51821 between the two transport hosts on IPsec/transit. Disable outbound NAT
for this isolated deployment and route the remote transport host toward the
endpoint. Retain pfSense's filtering. Do not disable certificate validation or
introduce PSK fallback. The Linux endpoint still requires XFRM reqid 42 for its
WG underlay input/output, independently of the appliance's policy.

**Mandatory appliance interlock:** deny WAN egress of the exact clear WG tuple.
Use quick, stateless rules for the exact WG peer pair and both UDP/51821 ports
on both LAN and enc0, in both directions. Floating keep-state entries can
otherwise bypass an outbound block when IPsec policies disappear. In this
pfSense version the later quick no-state rules override its earlier nonquick
enc0 keep-state rule. Inspect the actual loaded rules, clear only stale test
peer-pair states, and prove that no WG state is created during protected traffic.
Do not change the global state policy or patch pfSense source.

The test-copy-only correction is
`../../scripts/operational/pfsense_deny_wg_fallback.php`. Copy it to the approved
appliance and invoke `php -f SCRIPT DISPOSABLE_VM_UUID` with the independently
recorded QEMU UUID. It rejects a wrong UUID, version or test NIC identity before
loading configuration, and requires the explicit P23 interface configuration.
It changes only the test WG rules and preserves IKE/ESP. It never configures an
original gateway automatically. Verify both peer directions after reload and
reboot; an IKE session alone does not qualify this interlock.

## Installed manifest and credentials

Build/install the normal base package and the optional native add-on. Do not
start or enable services automatically. Extend the existing private, current-boot
manifest with these fields while retaining every explicit V2/AA field:

```json
{
  "profile": "DISPOSABLE_PFSENSE",
  "production_admission": false,
  "external_gateway": {
    "wan": {"name": "p23-wan", "mac": "52:54:00:23:02:01"},
    "lan": {"name": "p23-lan", "mac": "52:54:00:23:02:02"}
  }
}
```

The example is a manifest fragment, not an authorization or a complete runnable
configuration. Use distinct test MAC identities and pin their actual values.
The guard requires a KVM/QEMU guest, root, the pinned current Linux boot ID,
private configuration and exactly the specified NIC identities or loopback after
the supervisor has moved them. A foreign or partially missing root NIC inventory
is rejected. Configure the disposable Linux seed without DHCP and with optional
NICs so offline boot does not wait for a DHCP server. Services never configure
Polaris networking.

Only endpoint credentials under the root-owned mode-0700 `credentials/e`
directory are needed in external mode. Its `swanctl.conf`, `private/identity.pem`,
`x509/identity.pem` and `x509ca/ca.pem` must be root-owned regular mode-0600 files.
Use the existing `config.profile()` endpoint profile and its exact selectors.
The native-gateway mode continues to require reciprocal `e` and `o` credentials.
The add-on does not generate credentials or authorize resources on installation.

`5gnexus native-start`, `native-status` and `native-stop` operate the same installed
systemd units. `native-status` is a bounded cached publisher observation. The
external adapter moves only pinned guest NICs into its fresh owned namespaces
and restores them on controlled stop. A guest network manager may bring the
restored NICs up; require their test IPv4 addresses/routes and all owned
namespaces/pins to be removed rather than treating link UP as authorization.

External health requires the owned local charon process identity, exact selected
IKE/CHILD state, UDP selectors bound to that CHILD, matching directional VICI and
XFRM SPIs, expected inner routes/addresses, and bidirectional ESP byte progress
around a fresh inner WG echo. Mixed children, stale SPIs and rekey overlap fail
closed. Appliance process liveness is not remotely asserted. Native V2/AA and the
original absolute grant/health deadlines remain independent requirements.

## Packet and recovery acceptance

Observe both directions at QEMU's `filter-dump` boundary on both private links.
Finalize the filters with successful QMP `object-del` before parsing the files.
Also capture Linux endpoint **egress** on `pub`, inner WG on both peers, transit
and both resource boundaries. A Linux physical ingress capture can include
post-XFRM decapsulated packets; it is not the authoritative wire boundary.
Finalize guest tcpdump processes with SIGINT and require successful exit, zero
reported drops and complete pcap records before removing their interfaces.
Unexpected capture or cleanup errors fail acceptance.

The external test operator supplies separately signed approvals. Slow diagnostic
snapshots belong outside short grant checks. Never extend an existing signed
deadline to accommodate a test. After expiry, follow the existing signed REVOKE,
RECOVER and fresh-approval protocol; an AA revocation must increase its separate
revocation counter. Both protocol rejections remain mandatory failures.

Prove actual protected TCP, zero pregrant admission, denied unauthorized ports,
an assigned-source plaintext probe arriving from the appliance transit link,
unchanged protected delivery after that negative probe and signed disconnect
before the original deadline. Correlate the plaintext probe in transit captures
with the actual DROP counter and its absence at protected boundaries. pfSense
must see WG ciphertext on transit and ESP on its untrusted link; bootstrap
DHCP/IPv6 frames in a whole-VM capture must be classified separately.

Record new CHILD SPIs and IKE identities for their respective rekeys, followed by
protected traffic under fresh approval. Exercise a controlled WAN outage long
enough for the original grant to expire, confirm zero permits, revoke AA policy
monotonically, restart the disposable appliance and explicitly re-initiate the
installed client's configured child. Recovered tunnels must remain denied until
new AA authorization and the correct signed native recovery/approval sequence.
Capture delivery after recovery, final disconnect, removal of owned state and
focused installed-service start/stop checks. This tests controlled operator
reconnection; it does not claim unattended appliance or orphan-state recovery.

See [P2.3 evidence](../../docs/testing/pfsense-installed-results.md) for actual run
verdicts, package hashes, retained failures and independent review. General IPv6,
other selectors, external production gateways and performance comparisons require
their own acceptance. Production security acceptance and website readiness remain
blocked.
