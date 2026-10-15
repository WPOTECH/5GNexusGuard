# Native Dual-Tunnel: IKEv2/ESP outside WireGuard

## Baseline audit, before implementation

STANDARD is the existing default, not a security certification. Source audit found:

* `proxy/EgressProxy.syncEgressBindings` automatically opens `new ServerSocket(port)`
  on wildcard addresses. The tunnel-specific bind does not remove this bypass.
* `api/MeshResource` exposes mutations without authentication; application.properties
  binds HTTP on 0.0.0.0:8443. Port 8443 does not imply TLS.
* `tunnel/TunnelManager` negotiates over HTTP. The signature covers concatenated
  service/node/public-key fields, not IP/endpoint, nonce or expiry. The response
  is unauthenticated. Debug signature logging and shell key derivation also exist.
* `TunnelNegotiationResource` checks membership but not active/expiry state;
  teardown is unauthenticated. Existing sessions are not reliably revoked.
* `LedgerStore` materialization does not enforce service-owner authorship on updates
  or revokes. Block verification is not per-entry authorization. Service policy
  bandwidth/concurrency comments do not constitute enforcement.
* STANDARD tunnel allocation is process-local, interface names can collide,
  partial setup lacks rollback, and connector teardown uses a different map key.

These findings constrain this feature. It does not repair or attest the entire
control plane. Do not expose the existing management/consensus interfaces to an
untrusted network. Ledger writers and host administrators remain trusted.

## Hybrid architecture and status

The intended production architecture is **outer IKEv2/IPsec ESP using strongSwan,
inner WireGuard**. Implementation is a bounded Linux provisioning primitive and
isolated lab, not a validated production deployment. `903684a` is the preserved
WG-over-WG experimental reference. `scripts/native-dual/` and
`docs/native-dual-results.md` remain unchanged; their historical results do not
validate this hybrid. New work lives in `scripts/ipsec-dual/`.

```text
endpoint dlip-e                    outer gateway dlip-o
app -> inner WG -> ESP === pub === strongSwan ESP termination
                     192.0.2.1/30   192.0.2.2/30
                                         |
                              inner WG ciphertext UDP/51821
                                         | transit 10.78.0.0/30
                                  inner gateway dlip-i
                                   WG termination
                                         | authorized TCP only
                                  resource dlip-r 10.80.0.2:8080
```

Endpoint inner transport source is 10.77.0.1/32 on loopback; inner gateway
transport address is 10.78.0.2. Policy-based IPsec tunnel selectors admit only
these /32s and UDP source/destination port 51821. Inner WG addresses are
10.79.0.1/32 and 10.79.0.2/32; resource traffic routes exclusively via WG.
There is no NAT, default route, host service listener or host-network attachment.
Namespace names differ from the experimental reference.

IKEv2 uses mutual certificate authentication, exact DNS SAN identities, a dedicated
test CA, AES-256-GCM/PRF-SHA384/ECP384 for IKE and AES-256-GCM/ECP384 for ESP.
MOBIKE is disabled in this fixed-address profile. Only IKE UDP/500, UDP/4500 and
ESP are permitted on the public link. The lab requires native ESP in its public
capture; NAT traversal interoperability is not tested. In the lab, certificates and RSA-3072
private keys are generated at runtime outside git, expire after two days and are
never suitable for production enrollment. The CA signing key is deleted after
issuance. The standalone native supervisor instead requires explicit protected
operator certificate profiles (`--credentials`); it never defaults to test PKI. Each daemon loads only its own private key and the outer CA. Inner WG
keys are independently generated Curve25519 keys; neither CA trust nor ledger
Ed25519 identity grants WG membership automatically.

The implementation follows the [strongSwan swanctl configuration reference](https://docs.strongswan.org/docs/5.9/swanctl/swanctlConf.html)
and [nftables IPsec expressions](https://netfilter.org/projects/nftables/manpage.html).
Each charon process has a separate VICI socket and private mount of `/run` to
avoid shared PID files. Automatic strongSwan routes are disabled; exact routes
are installed by the supervisor. No session keys are included in diagnostics:
`ip xfrm state` output must not be exported.

## Product modes and authorization boundary

`mesh.access.mode=STANDARD` remains the default. `NATIVE_DUAL` now denotes the
hybrid transport and retains the guards on STANDARD listener/negotiation paths.
Unknown mode or native gateway-mode values fail startup. Restart and remove any
old STANDARD interfaces/listeners before changing modes.

| Native gateway mode | Behavior |
| --- | --- |
| `NATIVE` (default) | Local ledger lease exporter enabled; separately provisioned strongSwan native gateway plus inner WG enforcement primitive |
| `EXTERNAL_CONFIG` | Legacy tunnels still disabled; no lease export; renderer supplies an endpoint profile for a compatible third-party IKEv2 gateway |

The HTTP connect response is 409 with explicit transport, gateway mode and
operator-provisioning requirement. It never reports an active hybrid connection.
Java does not launch Docker, enroll certificates, configure appliances, or create
these namespaces. The renderer is an operator tool; gateway mode is not an
automatic appliance integration. External deployments must separately implement
inner WG forwarding and timed authorization. Local enforcement is deliberately
not advertised or enabled by configuration-only external mode.

The exporter consumes the existing local LedgerStore: active owned TCP service
at exactly `10.80.0.2:8080`, active owner/client registrations, explicit membership,
encryption enabled, unexpired policy, and no unsupported bandwidth/concurrency
constraints. It writes a private atomic version-2 lease with transport
`IKEV2_ESP_WIREGUARD` and the pinned service/client/owner tuple. The new consumer
rejects legacy, other-transport, malformed, denied, stale, future-dated, wrong-tuple,
symlinked or permissively readable leases. The preserved version-1 experimental
consumer rejects new leases. Run the historical checkpoint to reproduce its
original exporter contract; do not relabel its WG-over-WG output as hybrid.

The native supervisor renews a timed nftables address set, capped at three seconds.
Both TCP directions check the set on every packet, including established flows.
Denial flushes it; exporter or supervisor death causes kernel expiry. The supervisor
reconciles only owned host routes removed by link-down and withholds leases if the
expected CHILD_SA is not installed; it retries the named SA at bounded intervals.
This is not a demonstrated daemon-crash restart manager. Scheduling latency and
clocks affect the bound; stale replicated ledger state is not detected.
Ledger administrators, protected directory ownership and local host administration
remain trusted. This is an enforcement extension, not new consensus or authenticated
enrollment. The persisted-ledger Java fixture bypasses network consensus; the packet
harness uses synthetic leases. Their passing separately would not establish an
end-to-end running product/exporter/supervisor integration.

## Fail-closed design and isolation

All namespace inet input/output/forward chains default drop, including IPv6.
Endpoint WG transport must match outbound IPsec reqid 42; decrypted endpoint
traffic and outer-gateway forwarding must match inbound/outbound IPsec policy.
Missing SAs/policies cannot permit plaintext fallback. Resource traffic is admitted
only through inner WG and a live authorization set. The outer gateway cannot
originate resource TCP, and no established-flow accept bypasses authorization.
Only exact service ports and routes are admitted. These properties were exercised
in the isolated native test for the captured intervals; they are not a deployment-
wide or external-gateway guarantee.

The launcher uses Docker `--network none`, read-only root, private tmpfs state,
no host mounts/devices/socket, no port publishing and no `--privileged`. It drops
all capabilities then adds NET_ADMIN (WG/XFRM/nft), NET_RAW (capture),
NET_BIND_SERVICE (IKE), SYS_ADMIN (named netns/private mounts), SETUID and SETGID
(tcpdump credential setup). This is the requested capability set for this harness,
not a measured minimal kernel capability proof. Docker's default seccomp remains;
AppArmor is explicitly unconfined because named namespaces require mount operations.
No SYS_MODULE is granted: required kernel support must already exist. SYS_ADMIN
and relaxed AppArmor remain significant trust: use a disposable Linux Docker host.
The scripts do not change host routes, sysctls, firewall or network namespace.
Docker image building requires package-network access and ordinary daemon storage.

## Threat model and limits

Outer gateway sees encrypted WG transport and metadata, not resource plaintext.
Inner gateway necessarily sees application plaintext. Separate key domains do not
protect against root on the shared host, endpoint compromise, colluding gateways,
malicious ledger writers, denial of service or traffic analysis. This bounded lab
is one IPv4 TCP service/client/owner; it does not provide multi-host packaging,
automated key binding, rotation/revocation infrastructure, roaming, IPv6 transport,
DNS or UDP services. MTU is conservatively 1280; broad PMTU/performance testing is
pending. Test CA issuance shares a filesystem with the lab operator; it is not an
HSM or physical gateway trust separation.

## Alternatives and future clients

Nested WireGuard was retained as an experimental reference but shares a protocol
implementation across layers. TLS at the application edge would not carry general
packet traffic and would change the existing proxy model. IPsec transport-mode
plus inner WG could be smaller, but the chosen narrowly selected tunnel-mode ESP
supports an explicit outer termination boundary and distinct peer address spaces.
A network-namespace/route-based XFRM interface design may be preferable for a
multi-service deployment, but was not imposed on the current product before
validating its existing ledger policy and privilege model. For mobile endpoints,
IKEv2 roaming/NAT-T, OS VPN entitlements, sleep/wake recovery, captive portals and
on-device secure key storage must be engineered and retested. This fixed-address
Linux namespace prototype is not a mobile client.

No pfSense device or VM has been tested. External mode expresses a compatibility
profile only; it is not evidence of pfSense or other appliance interoperability.
There is no claim of government approval, certification or production readiness.
See [operation instructions](../../scripts/ipsec-dual/README.md) and
[executed results](../testing/native-dual-tunnel-results.md).
