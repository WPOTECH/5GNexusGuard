package com.defenderlink.mesh.tunnel.nativeaccess;

import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class NativeIssuanceV2Test {
    static KeyPair key() throws Exception { return KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); }
    static byte[] raw(KeyPair pair) { return Arrays.copyOfRange(pair.getPublic().getEncoded(), 12, 44); }
    static byte[] sign(KeyPair pair, byte[] bytes) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(pair.getPrivate()); signature.update(bytes); return signature.sign();
    }
    @Test void anIssuerCannotBeCreatedWithoutTrustedScope() throws Exception {
        KeyPair operator = key(), node = key();
        assertThrows(IllegalArgumentException.class,
                () -> new NativeIssuanceV2(raw(operator), raw(node)));
    }

    @Test void operatorAndNodePinsMustBeDistinct() throws Exception {
        KeyPair operator = key();
        assertThrows(IllegalArgumentException.class,
                () -> new NativeIssuanceV2(raw(operator), raw(operator), "svc", "a".repeat(64), "tcp:10.80.0.2:8080"));
    }

    @Test void explicitFreshOperatorApprovalOnlyAndCanonicalCrossLanguageBytes() throws Exception {
        KeyPair operator = key(), node = key();
        var payload = new NativeIssuanceV2.Payload(2, "IKEV2_ESP_WIREGUARD", "svc", "a".repeat(64),
                HexFormat.of().formatHex(raw(node)), "123e4567-e89b-12d3-a456-426614174000",
                "c".repeat(32), 7, 1_000_000_000L, 2_000_000_000L,
                "tcp:10.80.0.2:8080", "d".repeat(32), HexFormat.of().formatHex(raw(operator)));
        String expected = "DEFENDERLINK-NATIVE-ISSUANCE-V2\nversion=2\ntransport=IKEV2_ESP_WIREGUARD\nserviceId=svc\nclientNodeId="
                + "a".repeat(64) + "\nownerNodeId=" + payload.ownerNodeId() + "\nbootId=" + payload.bootId()
                + "\nnonce=" + "c".repeat(32) + "\ngeneration=7\nissuedBoottimeNs=1000000000\ndeadlineBoottimeNs=2000000000"
                + "\nresource=tcp:10.80.0.2:8080\nissuanceId=" + "d".repeat(32)
                + "\nissuerId=" + payload.issuerId() + "\n";
        assertArrayEquals(expected.getBytes(StandardCharsets.US_ASCII), NativeIssuanceV2.canonical(payload));
        var issuer = new NativeIssuanceV2(raw(operator), raw(node), "svc", "a".repeat(64), "tcp:10.80.0.2:8080");
        byte[] approval = sign(operator, NativeIssuanceV2.canonical(payload));
        assertThrows(SecurityException.class, () -> issuer.issue(payload, approval, bytes -> signUnchecked(node, bytes), 1_100_000_000L));
        issuer.expect(payload.bootId(), payload.nonce());
        var issued = issuer.issue(payload, approval, bytes -> signUnchecked(node, bytes), 1_100_000_000L);
        assertEquals(Base64.getEncoder().encodeToString(approval), issued.operatorSignature());
        assertTrue(com.defenderlink.mesh.identity.NodeIdentity.verify(
                NativeIssuanceV2.nodeMessage(NativeIssuanceV2.canonical(payload), approval),
                Base64.getDecoder().decode(issued.nodeSignature()), raw(node)));
        assertThrows(SecurityException.class, () -> issuer.issue(payload, approval, bytes -> signUnchecked(node, bytes), 1_100_000_000L));
        var reused = new NativeIssuanceV2.Payload(2, payload.transport(), payload.serviceId(), payload.clientNodeId(),
                payload.ownerNodeId(), payload.bootId(), "e".repeat(32), 8,
                payload.issuedBoottimeNs(), payload.deadlineBoottimeNs(), payload.resource(),
                payload.issuanceId(), payload.issuerId());
        issuer.expect(reused.bootId(), reused.nonce());
        byte[] newlyApproved = sign(operator, NativeIssuanceV2.canonical(reused));
        assertThrows(SecurityException.class, () -> issuer.issue(reused, newlyApproved,
                bytes -> signUnchecked(node, bytes), 1_100_000_000L));
    }
    static byte[] signUnchecked(KeyPair key, byte[] data) {
        try { return sign(key, data); } catch (Exception e) { throw new IllegalStateException(e); }
    }
    @Test void javaEnvelopeIsVerifiedByRealPythonReceiver() throws Exception {
        KeyPair operator = key(), node = key();
        String boot = "123e4567-e89b-12d3-a456-426614174000", nonce = "c".repeat(32);
        var p = new NativeIssuanceV2.Payload(2, "IKEV2_ESP_WIREGUARD", "svc", "a".repeat(64),
                HexFormat.of().formatHex(raw(node)), boot, nonce, 7, 1_000_000_000L, 2_000_000_000L,
                "tcp:10.80.0.2:8080", "d".repeat(32), HexFormat.of().formatHex(raw(operator)));
        var issuer = new NativeIssuanceV2(raw(operator), raw(node), "svc", "a".repeat(64), p.resource());
        issuer.expect(boot, nonce);
        byte[] approval = sign(operator, NativeIssuanceV2.canonical(p));
        var envelope = issuer.issue(p, approval, bytes -> signUnchecked(node, bytes), 1_100_000_000L);
        String script = """
                import json, sys
                sys.path.insert(0, sys.argv[1])
                from issuance_v2 import verify
                value = json.load(sys.stdin)
                p = value['payload']
                scope = {key:p[key] for key in ('serviceId','clientNodeId','ownerNodeId','bootId','resource')}
                result = verify(value, bytes.fromhex(sys.argv[2]), bytes.fromhex(sys.argv[3]),
                                scope, sys.argv[4], 6, 1100000000)
                print(result if result is not None else 'DENY')
                """;
        Process process = new ProcessBuilder("/usr/bin/python3", "-c", script,
                Path.of("scripts/ipsec-dual").toAbsolutePath().toString(),
                HexFormat.of().formatHex(raw(operator)), HexFormat.of().formatHex(raw(node)), nonce)
                .redirectErrorStream(true).start();
        try (var stdin = process.getOutputStream()) {
            stdin.write(new ObjectMapper().writeValueAsBytes(envelope));
        }
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        assertEquals(0, process.waitFor(), output);
        assertEquals("2000000000", output);
    }

    @Test void forgedAlteredExpiredRebootAndDelayedApprovalDeny() throws Exception {
        KeyPair operator = key(), node = key(), attacker = key();
        var p = new NativeIssuanceV2.Payload(2, "IKEV2_ESP_WIREGUARD", "svc", "a".repeat(64),
                HexFormat.of().formatHex(raw(node)), "123e4567-e89b-12d3-a456-426614174000",
                "c".repeat(32), 7, 1_000_000_000L, 2_000_000_000L,
                "tcp:10.80.0.2:8080", "d".repeat(32), HexFormat.of().formatHex(raw(operator)));
        var issuer = new NativeIssuanceV2(raw(operator), raw(node), "svc", "a".repeat(64), "tcp:10.80.0.2:8080");
        issuer.expect(p.bootId(), p.nonce());
        byte[] approved = sign(operator, NativeIssuanceV2.canonical(p));
        assertThrows(SecurityException.class, () -> issuer.issue(p, sign(attacker, NativeIssuanceV2.canonical(p)), b -> signUnchecked(node, b), 1_100_000_000L));
        assertThrows(SecurityException.class, () -> issuer.issue(new NativeIssuanceV2.Payload(2, p.transport(), "other", p.clientNodeId(), p.ownerNodeId(), p.bootId(), p.nonce(), 7, p.issuedBoottimeNs(), p.deadlineBoottimeNs(), p.resource(), p.issuanceId(), p.issuerId()), approved, b -> signUnchecked(node, b), 1_100_000_000L));
        assertThrows(SecurityException.class, () -> issuer.issue(p, approved, b -> signUnchecked(node, b), 2_000_000_000L));
        assertThrows(SecurityException.class, () -> issuer.issue(p, approved, b -> signUnchecked(node, b), 4_000_000_000L));
        assertThrows(SecurityException.class, () -> issuer.issue(new NativeIssuanceV2.Payload(2, p.transport(), p.serviceId(), p.clientNodeId(), p.ownerNodeId(), "123e4567-e89b-12d3-a456-426614174001", p.nonce(), 7, p.issuedBoottimeNs(), p.deadlineBoottimeNs(), p.resource(), p.issuanceId(), p.issuerId()), approved, b -> signUnchecked(node, b), 1_100_000_000L));
        assertThrows(IllegalArgumentException.class, () -> NativeIssuanceV2.canonical(
                new NativeIssuanceV2.Payload(2, p.transport(), p.serviceId(), p.clientNodeId(), p.ownerNodeId(),
                        p.bootId(), p.nonce(), 7, 1, Long.MAX_VALUE, p.resource(), p.issuanceId(), p.issuerId())));
    }
}
