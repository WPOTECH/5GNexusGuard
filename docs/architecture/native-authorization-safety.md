# Native authorization safety contract — BLOCKED design gate

This is an engineering contract, not implemented enforcement or acceptance. The
IKEv2/IPsec ESP outer and WireGuard inner remain unchanged. STANDARD remains the
default. Until the conditions below are implemented and packet-validated, native
DUAL_TUNNEL must not be advertised as a validated security boundary.

## Required invariants

1. A grant has a unique, authenticated policy generation, original bounded
   expiration, service/owner/client/resource tuple, and current enforcement
   epoch. The receiver rejects malformed, mismatched, revoked, out-of-order,
   expired and replayed generations. The issuer cannot simply refresh a
   generation's expiration on each scheduled export.
2. A grant accepted during one boot is bound to a CLOCK_BOOTTIME deadline at
   admission. Reconciliation and process restart preserve or shorten that
   deadline; they cannot derive a new one from a wall-clock sample. A boot
   change or loss of binding state denies until a *new* authorized issuance
   event establishes fresh authority. A new boot ID alone is not a grant.
3. Packet admission requires four independently verified predicates: an
   unexpired authorization, a short unexpired control-plane health observation,
   an active correctly matched cryptographic CHILD_SA, and an exact resource
   policy. An XFRM SA or WireGuard handshake alone grants no resource access.
4. Both directions, fragments and established connections traverse the same
   packet gate. Revocation and expiration affect existing connections as well
   as new SYNs. Packet traffic itself never refreshes a deadline.
5. Missing verification state, a missing enforcement program/hook, an ambiguous
   reboot or failed issuance must deny by default. Revocation is monotonic for
   its generation and cannot be undone by replaying an old allow record.

## Current authority gap

`NativePolicyExporter.refresh()` now writes an atomic, deny-only version-2
compatibility record; it does not consult the materialized ledger or issue a
rolling allow. The legacy synthetic packet lab still computes wall-clock lease
remaining time and installs a relative nft element plus `meta time` rule. The
actual operator-mode supervisor **denies every legacy export and standalone V2
envelope**, regardless of SA/route readiness (`native.py:renew_authorization`);
this is a deliberate availability loss, not a functioning V2 packet gate.
`NodeIdentity` creates private real key files and rejects mismatched keys, but
key custody alone cannot authorize a caller to request a signature.
`LedgerStore` reconstructs service state on restart; its materialized service
record does not retain the authorizing block generation. It accepts signed
blocks but does not authorize each ServiceUpdate or ServiceRevoke as an operation
by the service owner (`LedgerStore.java:141–178,268–297`). A service policy may
have no `expiresAt` at all (`LedgerEntry.java:123–131`). Thus a stale persistent
record and a new exporter process can look identical to an actual fresh grant
when the wall clock moves backward. Sampling BOOTTIME after receiving it cannot
recover the missing provenance. An in-memory high-water mark disappears on
restart; a persisted BOOTTIME value is not meaningful across boots.

The selected authority for V2 is a separately administered native 5GNexusGuard
Authorization Authority (AA), distinct from the endpoint and supervisor. Its
per-(node,scope) generation, revocation and enforcement-epoch high-water state
must be durably committed before an attestation is acknowledged. The existing
separately pinned Ed25519 operator approval remains necessary for grants and
recovery; the node key only countersigns transport. Node↔AA requests must use
mutually authenticated TLS with separately provisioned certificates, and a
fresh challenge-bound, AA-signed response. An opt-in AA implementation and
ephemeral-PKI tests are in `scripts/ipsec-dual/authorization_aa_v2.py` and
`AUTHORIZATION_AA_V2.md`. The native operator now has an explicitly configured
supervisor-to-AA control plane and isolated Java/AA/supervisor test, but still
calls the packet gate with DENY on every loop. No commercial service, TPM,
production URL or PKI is assumed. An ordinary local or AA-host database
cannot prove it has not been wholly restored to an older valid snapshot;
production rollback resistance stays BLOCKED until independent storage
protection and recovery are validated. No scheduled exporter refresh,
unauthenticated HTTP request, reconstructed ledger state or local root-owned
file can act as approval.

A functioning deployed V2 protocol therefore requires a verifiable
fresh issuance authority, not just new JSON fields. The issuer must sign the
complete authorization tuple, an operator-approved policy generation, original
lifetime, and a receiver-challenged boot/session binding. The receiver must
verify the signature, the issuer's right to authorize that resource, the
current session, durable generation/revocation high-water state, and a trusted
bound on the original lifetime. Same-generation re-publication cannot extend
it. A supervised restart may resume only an authenticated same-boot binding
whose original deadline and revocation state survived atomically. A reboot must
reject old bindings until a new, actually authorized event occurs after boot.
An automatically re-signed old service record is **not** that event. If policy
has a wall-clock expiry, the issuer needs trustworthy time at initial issuance;
otherwise it must issue an independently bounded relative lifetime from a
freshly authenticated event. Without that authority, deny rather than guessing.

## Disconnected V2 admission slice

`NativePolicyExporter.issueApproved` verifies a separately pinned operator
signature and a supervisor-signed challenge before node countersigning; it is
an explicit static library call, not a wired product endpoint. The Python
`admission_v2.py` library supports DENIED → PENDING_FRESH_APPROVAL → AUTHORIZED
→ EXPIRED/REVOKED with signed RECOVER and REVOKE operations, a private fsynced
journal, boot/session/nonce/scope checks and restart quarantine. The Java test
hands a real exporter-issued envelope to Python admission with ephemeral keys;
this proves the isolated signature/state transition, not a deployed operator
or data-plane authorization. Its caller still supplies boot ID, BOOTTIME and
key custody. See `scripts/ipsec-dual/ADMISSION_V2.md` for the exact format,
recovery rules and tests. A whole-file journal rollback is not detectable
without an independent monotonic anchor; after any restart, no persisted grant
is reactivated, and a fresh signed operator RECOVER plus a separate signed
allow is required. This safe denial does **not** establish durable rollback
resistance or a production-ready operator channel.

## Opt-in AA supervisor control plane (no packet admission)

With explicit private configuration, `native.py` constructs `native_control_v2.Controller` using the kernel boot UUID and `CLOCK_BOOTTIME`, a fresh supervisor session, operator/node/supervisor pins and a separate AA response pin. It reads signed operations and Java V2 envelopes from a private atomic spool, journals admission decisions, and uses hostname-checked node mTLS to request a newly challenged AA-signed attestation. The AA scope is a domain-separated digest of the complete service/client/owner/resource tuple, not a service-only label. It persists observed AA generation/revocation/epoch floors before reporting informational `ATTESTED`; restart begins denied, with new signed operator recovery and approval required. These local files do not prove whole-history rollback resistance.

`NativeControlAaIntegrationTest` invokes the real Java `NativePolicyExporter.issueApproved` through a private JSON-lines fixture with ephemeral keys, a running loopback AA HTTPS server, and the actual operator-mode `native.renew_authorization` decision. It tests signed recovery, grant, expiry, forced AA re-attestation after revocation, local revocation, restart, renewed approval and AA unavailability. The resulting control-plane decision never changes the unconditional `topology.authorize(0)` packet denial. This is an isolated JUnit process and Python supervisor module, not a deployed product JVM/ledger-to-native channel or independently administered AA host. Revocation is visible on the next attestation, not instantaneously after an already delivered response. Production packet admission remains disabled; see `scripts/ipsec-dual/NATIVE-AA-CONTROL-V2.md` for trust and recovery details.

## Kernel gate and evidence required before closure

A candidate per-packet gate could compare `bpf_ktime_get_boot_ns()` to *distinct*
immutable authorization and short health deadlines, but that alone is not an
accepted implementation. The exact deployed kernel (observed on the development
host: Linux 7.0.0-38-generic, nftables 1.1.6, bpftool 7.7.0) must be tested for
helper availability, attachment, restart, suspend/resume and both packet paths.
The default-deny firewall must remain effective even if a program is detached;
a missing BPF map check inside a detached program cannot help. A marked packet
cannot be trusted merely because its mark is set. Neither nft `meta time` nor
reinstalling a relative timeout after a slow userspace check establishes a
rollback-resistant absolute BOOTTIME bound.

Health renewal must require a positively observed live owned daemon, fresh VICI
responses for matching IKE/CHILD_SA peers, routes and exact resource policy; it
must not rely on cached XFRM state. Race after the last observation is handled by
an independently expiring short kernel deadline, whose maximum includes
observation-to-install delay. Lost heartbeat, supervisor death, program detach,
rekey and simultaneous peer failures require packet-level negative controls.
The isolated unrevoked daemon-death control in
`/home/wpotech/.hermes/cache/scratch/ipsec-dual-p0-sa-window-1/faults/surviving-sa-window.txt`
observed application delivery 2.247 s after charon was reaped; first denied
probe began 2.300 s after SIGKILL and timed out at 3.368 s. These are application
probe brackets, not an exact first-denied-packet timestamp or a safe bound.

The actual Java exporter → native supervisor → packet path, rollback/restart/
reboot/replay tests, active-flow expiry and an independent challenge review are
all required before either HIGH finding can be closed. No host clock changes,
global XFRM flush, unapproved privilege escalation or public-site changes are
part of this contract.
