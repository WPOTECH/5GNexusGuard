package com.defenderlink.mesh.tunnel.nativeaccess;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Two independent children: real Java exporter -> loopback AA/native-controller Python fixture. */
class NativeExporterCliIntegrationTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static String b64(byte[] bytes) { return Base64.getEncoder().encodeToString(bytes); }
    private static KeyPair key() throws Exception { return KeyPairGenerator.getInstance("Ed25519").generateKeyPair(); }
    private static String raw(KeyPair key) { return HexFormat.of().formatHex(Arrays.copyOfRange(key.getPublic().getEncoded(), 12, 44)); }

    private static final class Child implements AutoCloseable {
        final Process process;
        final BufferedWriter input;
        final BufferedReader output;
        Child(String... command) throws Exception {
            process = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            input = new BufferedWriter(new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
            output = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
        }
        JsonNode rawCall(Map<String, ?> request) throws Exception {
            input.write(JSON.writeValueAsString(request)); input.newLine(); input.flush();
            String line = output.readLine();
            assertNotNull(line, "child terminated before JSON response");
            return JSON.readTree(line);
        }
        JsonNode call(Map<String, ?> request) throws Exception {
            JsonNode result = rawCall(request);
            assertFalse(result.has("error"), "child denied request: " + result.path("error").asText());
            return result;
        }
        @Override public void close() throws Exception {
            input.close();
            if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly();
            assertEquals(0, process.exitValue());
        }
    }

    @Test void separateJavaExporterAndPythonAuthorityAttestWithoutOpeningPacketGate() throws Exception {
        KeyPair operator = key(), node = key(), supervisor = key();
        String classpath = System.getProperty("java.class.path");
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        try (Child python = new Child("/usr/bin/python3", "-u", Path.of("scripts/ipsec-dual/native_aa_java_harness.py").toAbsolutePath().toString());
             Child exporter = new Child(java, "-cp", classpath,
                     "com.defenderlink.mesh.tunnel.nativeaccess.NativePolicyExporterCli")) {
            Map<String, Object> keys = Map.of("operatorPkcs8", b64(operator.getPrivate().getEncoded()),
                    "nodePkcs8", b64(node.getPrivate().getEncoded()),
                    "supervisorPkcs8", b64(supervisor.getPrivate().getEncoded()));
            JsonNode state = python.call(new HashMap<>() {{ put("action", "init"); putAll(keys); }});
            assertEquals("DENIED", state.path("status").asText());
            assertFalse(state.path("packetGateEnabled").asBoolean());
            Map<String, Object> init = new HashMap<>(keys);
            init.remove("supervisorPkcs8"); // Java only needs the pinned supervisor public key.
            init.putAll(Map.of("action", "init", "serviceId", "svc", "clientNodeId", "a".repeat(64),
                    "resource", "tcp:10.80.0.2:8080", "sessionId", state.path("challenge").path("sessionId").asText(),
                    "operatorPublic", raw(operator), "nodePublic", raw(node), "supervisorPublic", raw(supervisor)));
            exporter.call(init);
            // Recovery is explicitly signed; the initial quarantine is never silently cleared.
            JsonNode challenge = state.path("challenge");
            Map<String, Object> op = new LinkedHashMap<>();
            op.put("action", "RECOVER");
            for (String field : List.of("bootId", "sessionId", "nonce", "serviceId", "clientNodeId", "ownerNodeId", "resource"))
                op.put(field, challenge.path(field).asText());
            op.put("generation", 1);
            StringBuilder text = new StringBuilder("DEFENDERLINK-NATIVE-OPERATION-V2\n");
            for (String field : List.of("action", "bootId", "sessionId", "nonce", "generation", "serviceId", "clientNodeId", "ownerNodeId", "resource"))
                text.append(field).append('=').append(op.get(field)).append('\n');
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(operator.getPrivate()); signer.update(text.toString().getBytes(StandardCharsets.US_ASCII));
            state = python.call(Map.of("action", "operation", "operation", op, "signature", b64(signer.sign())));
            assertEquals("DENIED", state.path("status").asText());
            long now = python.call(Map.of("action", "clock")).path("nowNs").asLong();
            var forged = state.path("challenge").deepCopy();
            ((com.fasterxml.jackson.databind.node.ObjectNode) forged).put("supervisorSignature", b64(new byte[64]));
            JsonNode rejected = exporter.rawCall(Map.of("action", "issue", "challenge", forged,
                    "generation", 2, "nowBoottimeNs", now, "lifetimeNs", 2_500_000_000L));
            assertEquals("SecurityException", rejected.path("error").asText(), "unsigned challenge must deny");
            JsonNode issued = exporter.call(Map.of("action", "issue", "challenge", state.path("challenge"),
                    "generation", 2, "nowBoottimeNs", now, "lifetimeNs", 2_500_000_000L));
            rejected = exporter.rawCall(Map.of("action", "issue", "challenge", state.path("challenge"),
                    "generation", 2, "nowBoottimeNs", now, "lifetimeNs", 2_500_000_000L));
            assertEquals("SecurityException", rejected.path("error").asText(), "reused generation must deny");
            assertEquals(raw(operator), issued.path("envelope").path("payload").path("issuerId").asText());
            assertEquals(raw(node), issued.path("envelope").path("payload").path("ownerNodeId").asText());
            state = python.call(Map.of("action", "grant", "envelope", issued.path("envelope")));
            assertEquals("ATTESTED", state.path("status").asText());
            assertFalse(state.path("packetGateEnabled").asBoolean());
            state = python.call(Map.of("action", "aa_revoke"));
            assertEquals("DENIED", state.path("status").asText());
            assertFalse(state.path("packetGateEnabled").asBoolean());
        }
    }
}
