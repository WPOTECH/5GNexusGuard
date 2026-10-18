package com.defenderlink.mesh.tunnel.nativeaccess;

import com.defenderlink.mesh.identity.NodeIdentity;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Function;

/** Standalone, explicit issuance primitive. No scheduler, ledger promotion, or packet allow. */
public final class NativeIssuanceV2 {
    public record Payload(int version, String transport, String serviceId, String clientNodeId,
                          String ownerNodeId, String bootId, String nonce, long generation,
                          long issuedBoottimeNs, long deadlineBoottimeNs, String resource,
                          String issuanceId, String issuerId) { }
    public record Envelope(Payload payload, String operatorSignature, String nodeSignature) { }

    private final byte[] operatorKey, nodeKey, supervisorKey;
    private final String expectedService, expectedClient, expectedResource, expectedSession;
    private String pendingBoot, pendingNonce;
    private long challengeNow;
    private long lastGeneration;
    private final java.util.Set<String> seenIssuanceIds = new java.util.HashSet<>();

    /** An unscoped issuer must never be usable. */
    @Deprecated
    public NativeIssuanceV2(byte[] operatorKey, byte[] nodeKey) {
        throw new IllegalArgumentException("trusted issuer scope required");
    }

    @Deprecated
    public NativeIssuanceV2(byte[] operatorKey, byte[] nodeKey,
                            String serviceId, String clientNodeId, String resource) {
        throw new IllegalArgumentException("supervisor pin and session required");
    }

    public NativeIssuanceV2(byte[] operatorKey, byte[] nodeKey, byte[] supervisorKey,
                            String serviceId, String clientNodeId, String resource, String sessionId) {
        if (operatorKey == null || nodeKey == null || supervisorKey == null
                || operatorKey.length != 32 || nodeKey.length != 32 || supervisorKey.length != 32
                || java.util.Arrays.equals(operatorKey, nodeKey)
                || java.util.Arrays.equals(operatorKey, supervisorKey)
                || java.util.Arrays.equals(nodeKey, supervisorKey)
                || !valid(serviceId, "[A-Za-z0-9._-]{1,128}")
                || !valid(clientNodeId, "[0-9a-f]{64}")
                || !valid(resource, "tcp:[0-9.]{7,15}:[0-9]{1,5}")
                || !valid(sessionId, "[A-Za-z0-9._-]{1,128}"))
            throw new IllegalArgumentException("invalid pin or trusted scope");
        this.operatorKey = operatorKey.clone(); this.nodeKey = nodeKey.clone(); this.supervisorKey = supervisorKey.clone();
        this.expectedService = serviceId; this.expectedClient = clientNodeId; this.expectedResource = resource;
        this.expectedSession = sessionId;
    }

    @Deprecated
    public synchronized void expect(String bootId, String nonce) {
        throw new SecurityException("unsigned challenge forbidden");
    }

    public static byte[] challengeBytes(String boot, String session, String nonce,
                                         String service, String client, String owner, String resource) {
        if (!valid(boot, "[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
                || !valid(session, "[A-Za-z0-9._-]{1,128}") || !valid(nonce, "[0-9a-f]{32}")
                || !valid(service, "[A-Za-z0-9._-]{1,128}") || !valid(client, "[0-9a-f]{64}")
                || !valid(owner, "[0-9a-f]{64}") || !valid(resource, "tcp:[0-9.]{7,15}:[0-9]{1,5}"))
            throw new IllegalArgumentException("invalid challenge");
        return ("DEFENDERLINK-NATIVE-CHALLENGE-V2\nbootId=" + boot + "\nsessionId=" + session
                + "\nnonce=" + nonce + "\nserviceId=" + service + "\nclientNodeId=" + client
                + "\nownerNodeId=" + owner + "\nresource=" + resource + "\n").getBytes(StandardCharsets.US_ASCII);
    }

    public synchronized void expectSigned(String boot, String nonce, byte[] signature, long nowBoottimeNs) {
        byte[] message = challengeBytes(boot, expectedSession, nonce, expectedService, expectedClient,
                java.util.HexFormat.of().formatHex(nodeKey), expectedResource);
        if (nowBoottimeNs <= 0 || signature == null || !NodeIdentity.verify(message, signature, supervisorKey))
            throw new SecurityException("untrusted supervisor challenge");
        pendingBoot = boot; pendingNonce = nonce; challengeNow = nowBoottimeNs;
    }

    private static boolean valid(String value, String pattern) { return value != null && value.matches(pattern); }

    public static byte[] canonical(Payload p) {
        if (p == null || p.version() != 2 || !"IKEV2_ESP_WIREGUARD".equals(p.transport())
                || !valid(p.serviceId(), "[A-Za-z0-9._-]{1,128}")
                || !valid(p.clientNodeId(), "[0-9a-f]{64}") || !valid(p.ownerNodeId(), "[0-9a-f]{64}")
                || !valid(p.bootId(), "[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
                || !valid(p.nonce(), "[0-9a-f]{32}") || p.generation() <= 0
                || !valid(p.resource(), "tcp:[0-9.]{7,15}:[0-9]{1,5}")
                || !valid(p.issuanceId(), "[0-9a-f]{32}") || !valid(p.issuerId(), "[0-9a-f]{64}")
                || p.issuedBoottimeNs() <= 0 || p.deadlineBoottimeNs() <= p.issuedBoottimeNs()
                || p.deadlineBoottimeNs() - p.issuedBoottimeNs() > 3_000_000_000L)
            throw new IllegalArgumentException("invalid issuance payload");
        return ("DEFENDERLINK-NATIVE-ISSUANCE-V2\nversion=2\ntransport=" + p.transport()
                + "\nserviceId=" + p.serviceId() + "\nclientNodeId=" + p.clientNodeId()
                + "\nownerNodeId=" + p.ownerNodeId() + "\nbootId=" + p.bootId()
                + "\nnonce=" + p.nonce() + "\ngeneration=" + p.generation()
                + "\nissuedBoottimeNs=" + p.issuedBoottimeNs()
                + "\ndeadlineBoottimeNs=" + p.deadlineBoottimeNs()
                + "\nresource=" + p.resource() + "\nissuanceId=" + p.issuanceId()
                + "\nissuerId=" + p.issuerId() + "\n").getBytes(StandardCharsets.US_ASCII);
    }

    public static byte[] nodeMessage(byte[] canonical, byte[] approval) {
        if (approval.length != 64) throw new IllegalArgumentException("invalid approval");
        byte[] prefix = "DEFENDERLINK-NATIVE-NODE-V2\n".getBytes(StandardCharsets.US_ASCII);
        byte[] result = new byte[prefix.length + canonical.length + approval.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(canonical, 0, result, prefix.length, canonical.length);
        System.arraycopy(approval, 0, result, prefix.length + canonical.length, approval.length);
        return result;
    }

    /** nowBoottimeNs must come from the trusted receiver's CLOCK_BOOTTIME, not wall time. */
    public synchronized Envelope issue(Payload p, byte[] approval, Function<byte[], byte[]> nodeSigner, long nowBoottimeNs) {
        byte[] bytes = canonical(p);
        if (pendingBoot == null || !pendingBoot.equals(p.bootId()) || !pendingNonce.equals(p.nonce())
                || p.generation() <= lastGeneration || seenIssuanceIds.contains(p.issuanceId())
                || !p.serviceId().equals(expectedService) || !p.clientNodeId().equals(expectedClient)
                || !p.resource().equals(expectedResource)
                || !p.issuerId().equals(java.util.HexFormat.of().formatHex(operatorKey))
                || !p.ownerNodeId().equals(java.util.HexFormat.of().formatHex(nodeKey))
                || nowBoottimeNs < challengeNow || nowBoottimeNs - challengeNow > 3_000_000_000L
                || nowBoottimeNs < p.issuedBoottimeNs() || nowBoottimeNs >= p.deadlineBoottimeNs()
                || approval == null || !NodeIdentity.verify(bytes, approval, operatorKey))
            throw new SecurityException("unapproved or stale issuance");
        // Consume before invoking a signer; exceptions must never leave the challenge reusable.
        pendingBoot = null; pendingNonce = null;
        byte[] signature = nodeSigner.apply(nodeMessage(bytes, approval));
        if (!NodeIdentity.verify(nodeMessage(bytes, approval), signature, nodeKey))
            throw new SecurityException("node key mismatch");
        lastGeneration = p.generation();
        seenIssuanceIds.add(p.issuanceId());
        return new Envelope(p, Base64.getEncoder().encodeToString(approval), Base64.getEncoder().encodeToString(signature));
    }
}
