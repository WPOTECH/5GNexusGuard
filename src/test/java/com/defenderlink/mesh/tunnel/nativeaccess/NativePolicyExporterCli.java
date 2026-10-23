package com.defenderlink.mesh.tunnel.nativeaccess;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

/**
 * Offline test-only JSON-lines child; never installed as an operator or packet gate.
 * Build with {@code mvn -q test-compile dependency:build-classpath -Dmdep.includeScope=test
 * -Dmdep.outputFile=/path/to/private/classpath.txt}, then launch with
 * {@code java -cp "target/test-classes:target/classes:$(</path/to/private/classpath.txt)"
 * com.defenderlink.mesh.tunnel.nativeaccess.NativePolicyExporterCli}.
 * Send init {action, operatorPkcs8, nodePkcs8, operatorPublic, nodePublic,
 * supervisorPublic, serviceId, clientNodeId, resource, sessionId} on stdin;
 * then issue {action, challenge, generation, nowBoottimeNs, lifetimeNs}.
 * Public pins are lowercase raw Ed25519 hex, private keys are base64 PKCS#8.
 * Only the signed envelope or a generic error is returned; never pass keys in argv.
 */
public final class NativePolicyExporterCli {
    private static final ObjectMapper JSON = new ObjectMapper();
    private NativeIssuanceV2 issuer;
    private PrivateKey operator, node;
    private String service, client, resource, owner, issuerId;

    private static String text(JsonNode object, String key) {
        JsonNode value = object.required(key);
        if (!value.isTextual()) throw new IllegalArgumentException("invalid field");
        return value.asText();
    }
    private static byte[] decode(String value) { return Base64.getDecoder().decode(value); }
    private static byte[] sign(PrivateKey key, byte[] data) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(key);
            signer.update(data);
            return signer.sign();
        } catch (GeneralSecurityException e) { throw new IllegalStateException("signing failed"); }
    }
    private static PrivateKey key(JsonNode request, String field) throws Exception {
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(decode(text(request, field))));
    }
    private JsonNode handle(JsonNode request) throws Exception {
        switch (text(request, "action")) {
            case "init" -> {
                if (issuer != null) throw new SecurityException("already initialized");
                byte[] operatorPin = HexFormat.of().parseHex(text(request, "operatorPublic"));
                byte[] nodePin = HexFormat.of().parseHex(text(request, "nodePublic"));
                byte[] supervisorPin = HexFormat.of().parseHex(text(request, "supervisorPublic"));
                service = text(request, "serviceId"); client = text(request, "clientNodeId");
                resource = text(request, "resource");
                NativeIssuanceV2 next = new NativeIssuanceV2(operatorPin, nodePin, supervisorPin,
                        service, client, resource, text(request, "sessionId"));
                PrivateKey operatorKey = key(request, "operatorPkcs8");
                PrivateKey nodeKey = key(request, "nodePkcs8");
                // Prove both private keys match the configured public pins before accepting init.
                byte[] probe = "DEFENDERLINK-TEST-KEY-PROBE".getBytes(StandardCharsets.US_ASCII);
                if (!com.defenderlink.mesh.identity.NodeIdentity.verify(probe, sign(operatorKey, probe), operatorPin)
                        || !com.defenderlink.mesh.identity.NodeIdentity.verify(probe, sign(nodeKey, probe), nodePin))
                    throw new SecurityException("key pin mismatch");
                operator = operatorKey; node = nodeKey; issuer = next;
                owner = HexFormat.of().formatHex(nodePin); issuerId = HexFormat.of().formatHex(operatorPin);
                return JSON.valueToTree(Map.of("ready", true));
            }
            case "issue" -> {
                if (issuer == null) throw new SecurityException("initialization required");
                JsonNode challenge = request.required("challenge");
                long now = request.required("nowBoottimeNs").asLong();
                long lifetime = request.required("lifetimeNs").asLong();
                if (lifetime <= 0 || lifetime > 3_000_000_000L || now <= 1_000_000L)
                    throw new IllegalArgumentException("invalid lifetime or clock");
                String boot = text(challenge, "bootId"), nonce = text(challenge, "nonce");
                if (!service.equals(text(challenge, "serviceId"))
                        || !client.equals(text(challenge, "clientNodeId"))
                        || !owner.equals(text(challenge, "ownerNodeId"))
                        || !resource.equals(text(challenge, "resource")))
                    throw new SecurityException("challenge scope mismatch");
                NativeIssuanceV2.Payload payload = new NativeIssuanceV2.Payload(2,
                        "IKEV2_ESP_WIREGUARD", service, client, owner, boot, nonce,
                        request.required("generation").asLong(), now - 1_000_000L,
                        Math.addExact(now, lifetime), resource,
                        UUID.randomUUID().toString().replace("-", ""), issuerId);
                NativeIssuanceV2.Envelope envelope = NativePolicyExporter.issueApproved(issuer, payload,
                        decode(text(challenge, "supervisorSignature")),
                        sign(operator, NativeIssuanceV2.canonical(payload)),
                        message -> sign(node, message), now);
                return JSON.valueToTree(Map.of("envelope", envelope));
            }
            default -> throw new IllegalArgumentException("unknown action");
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 0) throw new IllegalArgumentException("secrets and options belong on stdin");
        NativePolicyExporterCli cli = new NativePolicyExporterCli();
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        BufferedWriter output = new BufferedWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8));
        for (String line; (line = input.readLine()) != null;) {
            JsonNode result;
            try { result = cli.handle(JSON.readTree(line)); }
            catch (Exception e) { result = JSON.valueToTree(Map.of("error", e.getClass().getSimpleName())); }
            output.write(JSON.writeValueAsString(result)); output.newLine(); output.flush();
        }
    }
}
