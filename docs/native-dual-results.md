# Native dual implementation results

Executed 2026-10-13 in this repository, OpenJDK 25.0.4.1 (Java release target 24),
Python 3, Linux, UID 1000. No commits/pushes or sibling repository edits.

## Executed checks

| Command | Result |
| --- | --- |
| `scripts/native-dual/check.sh -o` | PASS, exit 0: Maven package and Quarkus augmentation; 6 Java tests, 0 failures/errors/skips; 3 Python tests passed; Python compilation passed |
| `bash -n scripts/native-dual/check.sh` | PASS |
| `python3 scripts/native-dual/native.py --help` | PASS |
| `git diff --check` | PASS |
| `python3 scripts/native-dual/integration.py` | BLOCKED, exit 77: requires root and NET_ADMIN/SYS_ADMIN; zero packet gates executed |
| `capsh --print` | Empty effective/bounding capabilities; no-new-privileges enabled |
| `unshare -Urn true` | BLOCKED, exit 1: Operation not permitted |
| `docker info --format '{{.ServerVersion}}'` | BLOCKED, exit 1: Docker socket permission denied |

Earlier `mvn -o test` compilation succeeded; final evidence is the complete check
script above, after adding all six tests. Maven warnings include the existing
Quarkus test artifact relocation, ignored `quarkus.http.cors` key, Java native/
Unsafe access warnings, and a test logging-manager initialization diagnostic.
They did not fail the build; this work does not repair those unrelated settings.

## What the passing tests establish

* Strict mode parsing and rejection of STANDARD entry points in native mode.
* Active owner/client/service, exact TCP binding, explicit allowedNodes, expiry,
  encryption and unsupported-policy rejection.
* Atomic private lease publication, revoked/missing service denial.
* A real RocksDB LedgerStore with signed blocks drives grant, membership removal,
  restoration and revocation into exported leases. Test entries bypass consensus;
  this does not validate entry authentication or network replication.
* Lease consumer rejects malformed, wrong-tuple, denied, expired, future-dated,
  wrong-owner, permissively readable and symlinked files.

## Gates still unverified

The included privileged harness has not executed the networking setup here.
Real WG handshakes/counters, independent peer behavior, nested packet captures,
resource reachability, public/port bypass denial, gateway failure, wrong-key
rejection, established-flow revocation, kernel expiry and cleanup are **not
claimed passing**. Run `sudo python3 scripts/native-dual/integration.py` on a
disposable capable Linux host before treating this implementation as verified.
An end-to-end running mesh exporter plus privileged supervisor deployment also
remains unexecuted; component tests and the synthetic packet harness are distinct.

## Changed files

* `docs/architecture/native-dual-tunnel.md`: source audit, threat model, architecture,
  trust boundary and explicit deployment limits.
* `docs/native-dual-results.md`: executed evidence and blockers.
* `scripts/native-dual/{native.py,integration.py,test_native.py,check.sh,README.md}`:
  actual native supervisor, reproducible data-plane harness, lease tests, build
  script and deployment instructions.
* `src/main/java/com/defenderlink/mesh/tunnel/nativeaccess/{AccessMode,NativePolicyExporter}.java`:
  mode switch and existing-ledger enforcement adapter.
* `src/main/java/com/defenderlink/mesh/{api/MeshResource,proxy/EgressProxy,tunnel/TunnelManager}.java`:
  native-mode guards; STANDARD remains default.
* `src/main/resources/application.properties`: optional configuration.
* `src/test/java/com/defenderlink/mesh/tunnel/nativeaccess/NativePolicyExporterTest.java`
  and `src/test/java/com/defenderlink/mesh/ledger/store/NativeLedgerFixture.java`:
  six policy/isolation tests, including persisted ledger integration.
* `pom.xml`: JUnit-platform-capable Surefire version, so tests actually execute.
* `.gitignore`: native runtime credentials/state and Python cache exclusions.

Tracked `target/` files modified by the build were restored to their initial
contents to avoid unrelated binary diffs. Re-run the build script before using
build outputs. STANDARD's audited security defects remain; neither the standard
path nor this unverified native deployment is represented as production secure.
