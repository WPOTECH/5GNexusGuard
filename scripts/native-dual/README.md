# Optional Linux native dual mode

Read [architecture and trust boundary](../../docs/architecture/native-dual-tunnel.md)
first. STANDARD stays default. This implementation is a single-host, four-netns,
one-service native deployment, not distributed gateway enrollment. The kernel
WireGuard implementation does real nested encryption. Applications must run in
`dlnd-e`; the protected resource must run in `dlnd-r` at `10.80.0.2:8080`.

## Build and tests

Requires JDK 24 or newer, Maven, Python 3.10+, Linux with WireGuard, iproute2,
nftables, and (packet tests only) tcpdump. On a disposable Debian/Ubuntu Linux
host the networking tools can be installed with:

```sh
sudo apt-get install iproute2 wireguard-tools nftables tcpdump python3
scripts/native-dual/check.sh        # use -o for cached Maven dependencies
sudo python3 scripts/native-dual/integration.py
```

The integration script needs root with NET_ADMIN and SYS_ADMIN and a writable
`/run/netns`. It creates only `dlnd-{e,o,i,r}`, refuses existing names, never
changes host firewall/routing, and removes its processes, keys, captures and
namespaces on normal exit. It runs real TCP echo servers on ports 8080 and 9090;
only 8080 may succeed. It tests handshakes/counters, distinct keys, packet
visibility, bypass/port denial, active-flow revocation, kernel lease expiry,
each layer down, wrong inner key and an injected fallback route. Exit 77 means
blocked before packet tests, not pass. A runtime failure exits 1.

The packet harness uses synthetic authorization to exercise enforcement. It is
**not** evidence of end-to-end product policy integration. Java tests separately
exercise the product exporter against a real RocksDB LedgerStore, signed block
append, allowedNodes updates and service revocation. No test claims to validate
consensus, entry authorship or authentication of the existing management API.

## Product deployment

Use a fresh isolated instance of the mesh owner process. Stop old STANDARD
processes and remove their listeners/interfaces first. Keep management and gossip
on a trusted management network: this feature does not authenticate those APIs.
Do not run the legacy systemd unit as the native supervisor; it lacks SYS_ADMIN.
Use separate foreground processes below (or equivalent locally reviewed units).

1. Register the owner and client identities through the existing ledger workflow.
   Record their full 64-character lowercase Ed25519 node IDs. Expose a TCP service
   with `localBind=10.80.0.2:8080` and allowedNodes containing the pinned client.
   The service must be owned by the exporting instance. There is no new policy
   database or HTTP fetch performed by the native supervisor.
2. Create `/run/defenderlink-native` mode 0700 owned by the mesh process user.
   The exporter writes `lease.json` atomically with mode 0600. Run the mesh owner
   without networking privileges; set these environment variables:

```sh
export MESH_ACCESS_MODE=NATIVE_DUAL
export MESH_NATIVE_SERVICE_ID=your-service
export MESH_NATIVE_CLIENT_NODE_ID=YOUR_64_HEX_CLIENT_NODE_ID
export MESH_NATIVE_LEASE_FILE=/run/defenderlink-native/lease.json
export QUARKUS_HTTP_HOST=127.0.0.1
java -jar target/quarkus-app/quarkus-run.jar
```

   Native mode disables wildcard legacy egress and STANDARD tunnel creation;
   `/api/connect/{id}` returns 409 explaining namespace access. STANDARD has no
   behavior change when the mode is absent. Spelling errors fail startup.
3. In another terminal, run the supervisor with the same service/client and the
   exporting owner's node ID. `--ledger-uid` is the numeric UID of the mesh process:

```sh
sudo python3 scripts/native-dual/native.py \
  --service your-service --client YOUR_64_HEX_CLIENT_NODE_ID \
  --owner YOUR_64_HEX_OWNER_NODE_ID --ledger-uid YOUR_MESH_UID
```

   Root-owned `/run/defenderlink-native-network` stores a lock and four independent
   ephemeral key files mode 0600. Keys are assigned to gateway WG interfaces in
   separate namespaces. Host root is trusted. Provisioning is local and static;
   the operator binds the endpoint keys to the pinned client ID. Possession of a
   node ID alone does not remotely enroll or configure a peer.
4. Start the actual resource only inside its namespace. For a disposable example:

```sh
sudo ip netns exec dlnd-r python3 -m http.server 8080 --bind 10.80.0.2 --directory /path/to/public-test-content
sudo ip netns exec dlnd-e curl --max-time 5 http://10.80.0.2:8080/
```

   Run application processes as an unprivileged UID inside their namespaces in
   deployment (e.g. `ip netns exec ... runuser -u app -- ...`). Do not serve secret
   working directories with the example HTTP server. No host/public resource
   port mapping is created. There is no DNS or general Internet route.
5. Remove the client from allowedNodes, revoke the service, or stop the mesh
   exporter: forwarding expires. Both directions of existing flows must match
   the timed authorization set. Stop the supervisor with SIGTERM to remove its
   topology; it also terminates processes launched in its namespaces.

The kernel timeout is at most three seconds after the last successful firewall
installation. Export refresh is one second and consumption every 200ms; normal
revocation should close earlier. Scheduling stalls/command latency can add delay
between lease validation and installation. Unsupported bandwidth/concurrency
policies deny instead of silently ignoring their constraints. Local ledger
staleness due to partition is not detectable by this adapter.

SIGKILL or host failure may leave namespace names and key files. The firewall
lease still expires without userspace. Inspect `ip netns list` and `ip netns pids
NAME`, stop remaining namespace processes, delete only the four `dlnd-*` names
and key files in `/run/defenderlink-native-network` belonging to this deployment,
then restart. The tool deliberately refuses to adopt or delete preexisting names.
Do not use `wg show all dump`: it exposes private key material.
