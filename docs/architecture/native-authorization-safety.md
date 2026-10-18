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

`NativePolicyExporter` still writes an atomic version-2 record containing
identities, an `allowed` bit and a rolling `expiresAtMs` derived from `Instant.now()`
(`NativePolicyExporter.java:40–67`). The legacy synthetic packet lab computes
remaining time with the current wall clock and installs a relative nft set element
and `meta time` rule. The actual operator-mode supervisor now **denies every
legacy export**, regardless of SA/route readiness (`native.py:renew_authorization`);
this is a deliberate availability loss, not a functioning V2 protocol. A
legacy signed/unsigned file cannot be enabled as a deployment workaround.
`NodeIdentity` now creates private real key files and rejects mismatched keys;
this secures local key handling but does not authorize callers to use the key.
The owner identity and file mode identify a local writer, not the freshness of
the underlying ledger operation.
`LedgerStore` reconstructs service state on restart; its materialized service
record does not retain the authorizing block generation. It accepts signed
blocks but does not authorize each ServiceUpdate or ServiceRevoke as an operation
by the service owner (`LedgerStore.java:141–178,268–297`). A service policy may
have no `expiresAt` at all (`LedgerEntry.java:123–131`). Thus a stale persistent
record and a new exporter process can look identical to an actual fresh grant
when the wall clock moves backward. Sampling BOOTTIME after receiving it cannot
recover the missing provenance. An in-memory high-water mark disappears on
restart; a persisted BOOTTIME value is not meaningful across boots.

The selected authority for V2 is an explicit post-boot operator approval signed
by a **separately pinned Ed25519 operator key**. The node's existing key may
countersign transport, but cannot substitute for operator authorization. No
scheduled exporter refresh, unauthenticated HTTP request, reconstructed ledger
state, or local root-owned file can produce this approval. The operator's public
key must be provisioned out-of-band and pinned; replacement, compromise and
revocation require an explicit operator procedure. The native receiver must
challenge each supervisor session and reject approvals from a previous session
or boot. This decision is a design input, **not an implemented V2 grant**.

A functioning version-3 protocol therefore requires an identified, verifiable
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
