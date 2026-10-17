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
