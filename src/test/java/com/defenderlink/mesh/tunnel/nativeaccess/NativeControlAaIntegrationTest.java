package com.defenderlink.mesh.tunnel.nativeaccess;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/** Real Java issuance -> private subprocess -> mTLS AA -> native controller, never a packet gate. */
class NativeControlAaIntegrationTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String CLIENT = "a".repeat(64), RESOURCE = "tcp:10.80.0.2:8080";
    private static byte[] raw(KeyPair key) { return Arrays.copyOfRange(key.getPublic().getEncoded(), 12, 44); }
    private static byte[] sign(KeyPair key, byte[] message) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key.getPrivate()); signer.update(message); return signer.sign();
    }
    private static String b64(byte[] value) { return Base64.getEncoder().encodeToString(value); }
    private static Map<String, Object> operation(JsonNode challenge, String action, int generation) {
        Map<String, Object> op = new LinkedHashMap<>();
        op.put("action", action);
        for (String field : List.of("bootId", "sessionId", "nonce", "serviceId", "clientNodeId", "ownerNodeId", "resource"))
            op.put(field, challenge.get(field).asText());
        op.put("generation", generation);
        return op;
    }
    private static byte[] operationBytes(Map<String, Object> op) {
        StringBuilder text = new StringBuilder("DEFENDERLINK-NATIVE-OPERATION-V2\n");
        for (String field : List.of("action", "bootId", "sessionId", "nonce", "generation", "serviceId", "clientNodeId", "ownerNodeId", "resource"))
            text.append(field).append('=').append(op.get(field)).append('\n');
        return text.toString().getBytes(StandardCharsets.US_ASCII);
    }
    private static final class Harness implements AutoCloseable {
        final Process process;
        final BufferedWriter input;
        final BufferedReader output;
        Harness() throws Exception {
            process = new ProcessBuilder("/usr/bin/python3", "-u",
                    Path.of("scripts/ipsec-dual/native_aa_java_harness.py").toAbsolutePath().toString())
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
            input = new BufferedWriter(new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
            output = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        }
        JsonNode call(Map<String, ?> value) throws Exception {
            input.write(JSON.writeValueAsString(value)); input.newLine(); input.flush();
            String line = output.readLine();
            assertNotNull(line, "private Python harness exited before responding");
            JsonNode result = JSON.readTree(line);
            assertFalse(result.has("error"), "harness error: " + result.path("error").asText());
            return result;
        }
        @Override public void close() throws Exception {
            input.close();
            if (!process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) process.destroyForcibly();
            assertEquals(0, process.exitValue(), "private harness exit");
        }
    }
    private static JsonNode signedOperation(Harness harness, KeyPair operator, JsonNode challenge,
                                            String action, int generation) throws Exception {
        Map<String, Object> op = operation(challenge, action, generation);
        return harness.call(Map.of("action", "operation", "operation", op,
                "signature", b64(sign(operator, operationBytes(op)))));
    }
    private static JsonNode grant(Harness harness, KeyPair operator, KeyPair node, KeyPair supervisor,
                                  JsonNode challenge, int generation, long lifetimeNs) throws Exception {
        long now = harness.call(Map.of("action", "clock")).get("nowNs").asLong();
        String owner = HexFormat.of().formatHex(raw(node));
        var payload = new NativeIssuanceV2.Payload(2, "IKEV2_ESP_WIREGUARD", "svc", CLIENT, owner,
                challenge.get("bootId").asText(), challenge.get("nonce").asText(), generation,
                now - 1_000_000L, now + lifetimeNs, RESOURCE,
                UUID.randomUUID().toString().replace("-", ""), HexFormat.of().formatHex(raw(operator)));
        var issuer = new NativeIssuanceV2(raw(operator), raw(node), raw(supervisor), "svc", CLIENT,
                RESOURCE, challenge.get("sessionId").asText());
        var envelope = NativePolicyExporter.issueApproved(issuer, payload,
                Base64.getDecoder().decode(challenge.get("supervisorSignature").asText()),
                sign(operator, NativeIssuanceV2.canonical(payload)), bytes -> {
                    try { return sign(node, bytes); } catch (Exception e) { throw new IllegalStateException(e); }
                }, now);
        return harness.call(Map.of("action", "grant", "envelope", envelope));
    }
    @Test void javaApprovalThroughRealMtlsAaAndControllerRemainsDenyOnlyAcrossLifecycle() throws Exception {
        KeyPair operator = NativeIssuanceV2Test.key(), node = NativeIssuanceV2Test.key(),
                supervisor = NativeIssuanceV2Test.key();
        try (Harness harness = new Harness()) {
            JsonNode state = harness.call(Map.of("action", "init",
                    "operatorPkcs8", b64(operator.getPrivate().getEncoded()),
                    "nodePkcs8", b64(node.getPrivate().getEncoded()),
                    "supervisorPkcs8", b64(supervisor.getPrivate().getEncoded())));
            assertEquals("DENIED", state.get("status").asText());
            assertFalse(state.get("packetGateEnabled").asBoolean());
            state = signedOperation(harness, operator, state.get("challenge"), "RECOVER", 1);
            assertEquals("DENIED", state.get("status").asText());
            state = grant(harness, operator, node, supervisor, state.get("challenge"), 2, 1_000_000_000L);
            assertEquals("ATTESTED", state.get("status").asText());
            assertFalse(state.get("packetGateEnabled").asBoolean());
            Thread.sleep(1200);
            state = harness.call(Map.of("action", "step"));
            assertEquals("DENIED", state.get("status").asText(), "local grant expiry");
            state = grant(harness, operator, node, supervisor, state.get("challenge"), 3, 2_500_000_000L);
            assertEquals("ATTESTED", state.get("status").asText());
            state = harness.call(Map.of("action", "aa_revoke"));
            assertEquals("DENIED", state.get("status").asText(), "AA revocation at the next forced attestation");
            assertFalse(state.get("packetGateEnabled").asBoolean());
            state = signedOperation(harness, operator, state.get("challenge"), "REVOKE", 4);
            assertEquals("DENIED", state.get("status").asText());
            state = harness.call(Map.of("action", "restart"));
            assertEquals("DENIED", state.get("status").asText());
            state = signedOperation(harness, operator, state.get("challenge"), "RECOVER", 5);
            assertEquals("DENIED", state.get("status").asText());
            state = grant(harness, operator, node, supervisor, state.get("challenge"), 6, 2_500_000_000L);
            assertEquals("ATTESTED", state.get("status").asText());
            state = harness.call(Map.of("action", "aa_down"));
            assertEquals("DENIED", state.get("status").asText());
            assertFalse(state.get("packetGateEnabled").asBoolean());
        }
    }
}
