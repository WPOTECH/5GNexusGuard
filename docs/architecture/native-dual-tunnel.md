# Native Dual-Tunnel Access (bounded Linux implementation)

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

## Scope and architecture

Opt-in `mesh.access.mode=NATIVE_DUAL`; default `STANDARD` retains existing behavior.
One statically provisioned IPv4 TCP service, one pinned client node, one owner,
one Linux kernel. Separate endpoint (`dlnd-e`), outer (`dlnd-o`), inner (`dlnd-i`),
and resource (`dlnd-r`) network namespaces. This is a local native deployment
primitive and reproducible lab, not automatic multi-host enrollment or UI support.
Applications run inside the endpoint namespace; the resource process runs inside
its own namespace. There is no host intercept or host resource listener.

```
application -> inner WG ciphertext -> outer WG ciphertext -> public veth
 endpoint                                             outer gateway
 inner WG <-------- encrypted inner UDP via private veth ------> inner gateway
                                                               inner WG
                                                                  |
                                                            resource netns
```

Outer WG: endpoint 10.77.0.1 <-> outer gateway 10.77.0.2.
Inner WG: endpoint 10.79.0.1 <-> inner gateway 10.79.0.2, UDP transported
through outer WG to 10.78.0.2:51821. Resource: 10.80.0.2:8080.
Four independently generated private keys; no key reuse between layers.
WG devices and sockets are created in their respective namespaces. Outer and
inner gateways have separate kernel routing/firewall state. Root on the shared
host can access all keys: this is not a defense against host-root compromise.

All namespace filter chains default drop (including IPv6). Exact /32 routes,
no default route, no NAT, no forwarding except explicit inner UDP at the outer
and authorized TCP at the inner. Endpoint resource traffic can only leave via
inner WG; inner UDP can only leave via outer WG. Interface loss cannot create a
plaintext fallback. Resource accepts only the inner client source and service
port. No public service publication, gateway proxy, or STANDARD tunnel is started
in native mode. Mode changes require restart and removal of old STANDARD
interfaces/listeners before adopting this deployment.

## Policy authority and trust

A product CDI component reads `LedgerStore` directly and atomically exports a
maximum three-second lease. It requires an active owned TCP service with exact
resource bind, active registered client and owner, explicit allowedNodes,
encryption enabled, unexpired policy, and no unsupported bandwidth/concurrency
constraints. Unknown or invalid mode fails startup. Native mode disables legacy
egress and both STANDARD tunnel creation paths. Existing HTTP connect does not
pretend that a native namespace is a host intercept.

The privileged native supervisor consumes this file, bound to the configured
service/client/owner tuple. A timed nftables set authorizes both directions on
every packet, including established connections. Denial flushes the set; missing,
malformed or stale exports deny; exporter/supervisor death expires kernel access.
This is a compatible local enforcement extension of existing ledger policy, not
an independent harness policy authority. Static keys are operator-bound to the
client identity in the protected configuration; there is no automated identity
to WG enrollment. A compromised ledger writer can still grant access. Filesystem
ownership and trusted local administration are part of the trust boundary.

Kernel authorization expires at most three seconds after its last installation;
lease validation to installation has scheduling/command latency. Revocation is
not instantaneous. A stale replicated ledger is not detected by this exporter;
only the local authority's view is enforced. Clock rollback/forward can affect
lease availability; the consumer caps accepted remaining duration to three seconds.

## Threat model and limitations

Protect against public-link observers/injection, plaintext route fallback,
unauthorized service ports, outer gateway inspection of resource plaintext,
and stale local authorizations after process death. Inner gateway necessarily
sees plaintext and resource metadata; the outer sees endpoint identity, timing,
volume and inner gateway destination. An attacker with both gateway keys or
host root defeats separation. Endpoint compromise exposes application data.
Denial of service, global traffic analysis, malicious ledger administrators,
control-plane authentication remediation, distributed deployment, roaming,
IPv6 transport, DNS, UDP services, key rotation and production packaging are
outside this bounded implementation. No claim of anonymity or production readiness.

See `scripts/native-dual/README.md` for operation and `docs/native-dual-results.md`
for executed evidence and blockers. Privileged packet tests are required before
claiming the data-plane gates pass.
