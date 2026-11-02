package com.defenderlink.mesh.tunnel.nativeaccess;

import com.defenderlink.mesh.identity.NodeIdentity;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class NativeV2InboxTest {
    @TempDir Path directory;
    final ObjectMapper json = new ObjectMapper();
    final KeyPair operator = NativeIssuanceV2Test.supervisorKey();
    final KeyPair supervisor = NativeIssuanceV2Test.supervisorKey();
    NodeIdentity node() throws Exception {
        var identity = new NodeIdentity();
        var field = NodeIdentity.class.getDeclaredField("dataDir"); field.setAccessible(true); field.set(identity, directory.toString());
        var init = NodeIdentity.class.getDeclaredMethod("init"); init.setAccessible(true); init.invoke(identity);
        return identity;
    }
    void write(String name, Object value) throws Exception {
        Path path = directory.resolve(name); json.writeValue(path.toFile(), value);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
    NativeIssuanceV2.Payload approval(NodeIdentity node, KeyPair signer, boolean expired) throws Exception {
        long now = NativeV2Inbox.boottime();
        String boot = Files.readString(Path.of("/proc/sys/kernel/random/boot_id")).trim();
        String nonce = "c".repeat(32), resource = "tcp:10.80.0.2:8080";
        byte[] challenge = NativeIssuanceV2.challengeBytes(boot, "installed-session", nonce,
                "svc", "a".repeat(64), node.getNodeId(), resource);
        write("challenge.json", Map.of("bootId", boot, "sessionId", "installed-session", "nonce", nonce,
                "serviceId", "svc", "clientNodeId", "a".repeat(64), "ownerNodeId", node.getNodeId(),
                "resource", resource, "supervisorSignature", Base64.getEncoder().encodeToString(NativeIssuanceV2Test.sign(supervisor, challenge))));
        var payload = new NativeIssuanceV2.Payload(2, "IKEV2_ESP_WIREGUARD", "svc", "a".repeat(64),
                node.getNodeId(), boot, nonce, 1, now - 100_000_000L,
                expired ? now - 1 : now + 1_500_000_000L, resource, "d".repeat(32),
                HexFormat.of().formatHex(NativeIssuanceV2Test.raw(operator)));
        write("approval.json", Map.of("payload", payload, "operatorSignature",
                Base64.getEncoder().encodeToString(NativeIssuanceV2Test.sign(signer, NativeIssuanceV2.canonical(payload)))));
        return payload;
    }
    NativeV2Inbox inbox(NodeIdentity node) {
        return new NativeV2Inbox(NativeIssuanceV2Test.raw(operator), NativeIssuanceV2Test.raw(supervisor), "svc", "a".repeat(64), node);
    }
    @Test void persistedIdentityCountersignsOnlyExactExternalApprovalOnce() throws Exception {
        NodeIdentity node = node(); var payload = approval(node, operator, false); var inbox = inbox(node);
        assertTrue(inbox.poll(directory)); assertFalse(inbox.poll(directory));
        var envelope = json.readTree(directory.resolve("inbox.json").toFile()).required("envelope");
        byte[] signature = Base64.getDecoder().decode(envelope.required("nodeSignature").asText());
        byte[] op = Base64.getDecoder().decode(envelope.required("operatorSignature").asText());
        assertTrue(NodeIdentity.verify(NativeIssuanceV2.nodeMessage(NativeIssuanceV2.canonical(payload), op), signature, node.getPublicKeyBytes()));
        assertEquals(payload.deadlineBoottimeNs(), envelope.required("payload").required("deadlineBoottimeNs").asLong());
        assertEquals(node.getNodeId(), node().getNodeId());
    }
    @Test void forgedApprovalDoesNotPublish() throws Exception {
        NodeIdentity node = node(); approval(node, NativeIssuanceV2Test.supervisorKey(), false);
        assertThrows(SecurityException.class, () -> inbox(node).poll(directory));
        assertFalse(Files.exists(directory.resolve("inbox.json")));
    }
    @Test void expiredApprovalDoesNotPublish() throws Exception {
        NodeIdentity node = node(); approval(node, operator, true);
        assertThrows(SecurityException.class, () -> inbox(node).poll(directory));
        assertFalse(Files.exists(directory.resolve("inbox.json")));
    }
    @Test void wrongCurrentNonceAndDuplicateFieldsDoNotPublish() throws Exception {
        NodeIdentity node = node(); approval(node, operator, false);
        Path challenge=directory.resolve("challenge.json");
        var value=json.readTree(challenge.toFile());
        ((com.fasterxml.jackson.databind.node.ObjectNode)value).put("nonce","e".repeat(32));
        write("challenge.json",value);
        assertThrows(SecurityException.class, () -> inbox(node).poll(directory));
        Path input=directory.resolve("approval.json");
        String content=Files.readString(input);
        Files.writeString(input,"{\"operatorSignature\":\"duplicate\","+content.substring(1));
        assertThrows(java.io.IOException.class, () -> inbox(node).poll(directory));
        assertFalse(Files.exists(directory.resolve("inbox.json")));
    }
    @Test void unsafeInputAndSymlinkAreRejected() throws Exception {
        NodeIdentity node = node(); approval(node, operator, false);
        Path input = directory.resolve("approval.json");
        Files.setPosixFilePermissions(input, PosixFilePermissions.fromString("rw-r--r--"));
        assertThrows(java.io.IOException.class, () -> inbox(node).poll(directory));
        Files.move(input, directory.resolve("target.json")); input.toFile().delete();
        Files.createSymbolicLink(input, directory.resolve("target.json"));
        assertThrows(java.io.IOException.class, () -> inbox(node).poll(directory));
        assertFalse(Files.exists(directory.resolve("inbox.json")));
    }
}
