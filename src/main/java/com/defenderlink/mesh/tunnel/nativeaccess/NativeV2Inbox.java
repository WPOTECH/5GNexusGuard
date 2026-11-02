package com.defenderlink.mesh.tunnel.nativeaccess;

import com.defenderlink.mesh.identity.NodeIdentity;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Private signed-approval IPC. No operator secret, grant generation, or packet allow. */
final class NativeV2Inbox {
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private final byte[] operator, supervisor;
    private final String service, client;
    private final NodeIdentity node;
    private String session, attempted;
    private NativeIssuanceV2 issuer;
    private final Set<String> consumed = new HashSet<>();

    NativeV2Inbox(byte[] operator, byte[] supervisor, String service, String client, NodeIdentity node) {
        this.operator = operator.clone(); this.supervisor = supervisor.clone();
        this.service = service; this.client = client; this.node = node;
        // Validate pins/scope at construction, even before an approval is present.
        new NativeIssuanceV2(operator, node.getPublicKeyBytes(), supervisor,
                service, client, "tcp:10.80.0.2:8080", "validation");
    }

    static long uid() throws IOException {
        for (String line : Files.readAllLines(Path.of("/proc/self/status")))
            if (line.startsWith("Uid:")) return Long.parseLong(line.trim().split("\\s+")[4]);
        throw new IOException("filesystem UID unavailable");
    }

    static void directory(Path path) throws IOException {
        long uid = uid();
        if (!path.isAbsolute() || !path.toRealPath().equals(path)
                || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                || ((Number) Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue() != uid
                || !Files.getPosixFilePermissions(path).equals(PosixFilePermissions.fromString("rwx------")))
            throw new IOException("private owned directory required");
        for (Path p = path.getParent(); p != null; p = p.getParent()) {
            int mode = ((Number) Files.getAttribute(p, "unix:mode", LinkOption.NOFOLLOW_LINKS)).intValue();
            long owner = ((Number) Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue();
            if (!Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS) || !p.toRealPath().equals(p)
                    || owner != 0 && owner != uid || (mode & 0022) != 0 && !(owner == 0 && (mode & 01000) != 0))
                throw new IOException("replaceable directory ancestor");
        }
    }

    static byte[] read(Path path) throws IOException {
        var before = Files.readAttributes(path, "unix:uid,mode,nlink,ino,dev,size", LinkOption.NOFOLLOW_LINKS);
        int mode = ((Number) before.get("mode")).intValue();
        if ((mode & 0170000) != 0100000 || (mode & 0777) != 0600
                || ((Number) before.get("uid")).longValue() != uid()
                || ((Number) before.get("nlink")).longValue() != 1
                || ((Number) before.get("size")).longValue() > 16384)
            throw new IOException("private regular input required");
        ByteBuffer data = ByteBuffer.allocate(16385);
        try (var channel = Files.newByteChannel(path, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            while (data.hasRemaining() && channel.read(data) != -1) { }
        }
        var after = Files.readAttributes(path, "unix:uid,mode,nlink,ino,dev,size", LinkOption.NOFOLLOW_LINKS);
        if (data.position() > 16384 || !before.equals(after)) throw new IOException("input changed during read");
        return Arrays.copyOf(data.array(), data.position());
    }

    /** Production time source is the local kernel CLOCK_BOOTTIME, never request data. */
    static long boottime() throws Exception {
        Process child = new ProcessBuilder("/usr/bin/python3", "-I", "-S", "-c",
                "import time;print(time.clock_gettime_ns(time.CLOCK_BOOTTIME))")
                .redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try {
            if (!child.waitFor(1, TimeUnit.SECONDS) || child.exitValue() != 0)
                throw new IOException("kernel clock unavailable");
            String result = new String(child.getInputStream().readNBytes(32), java.nio.charset.StandardCharsets.US_ASCII).trim();
            if (!result.matches("[0-9]{1,19}")) throw new IOException("invalid kernel clock");
            return Long.parseLong(result);
        } finally { if (child.isAlive()) child.destroyForcibly(); }
    }

    synchronized boolean poll(Path directory) throws Exception {
        directory(directory);
        byte[] request;
        try { request = read(directory.resolve("approval.json")); }
        catch (NoSuchFileException absent) { return false; }
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(request));
        if (digest.equals(attempted)) return false;
        attempted = digest; // Invalid/stale inputs are not repeatedly retried.
        JsonNode approval = JSON.readTree(request);
        if (!fields(approval).equals(Set.of("payload", "operatorSignature"))) throw new SecurityException("invalid approval");
        JsonNode challenge = JSON.readTree(read(directory.resolve("challenge.json")));
        String kernelBoot = Files.readString(Path.of("/proc/sys/kernel/random/boot_id")).trim();
        NativeIssuanceV2.Payload payload = JSON.treeToValue(approval.required("payload"), NativeIssuanceV2.Payload.class);
        if (!kernelBoot.equals(payload.bootId()) || !kernelBoot.equals(challenge.required("bootId").asText())
                || !payload.nonce().equals(challenge.required("nonce").asText())
                || !service.equals(challenge.required("serviceId").asText())
                || !client.equals(challenge.required("clientNodeId").asText())
                || !node.getNodeId().equals(challenge.required("ownerNodeId").asText())
                || !"tcp:10.80.0.2:8080".equals(challenge.required("resource").asText()))
            throw new SecurityException("challenge scope mismatch");
        String nextSession = challenge.required("sessionId").asText();
        if (!nextSession.equals(session)) {
            issuer = new NativeIssuanceV2(operator, node.getPublicKeyBytes(), supervisor,
                    service, client, "tcp:10.80.0.2:8080", nextSession);
            session = nextSession;
        }
        if (consumed.size() >= 4096 || consumed.contains(payload.issuanceId()))
            throw new SecurityException("issuance replay or process quota");
        NativeIssuanceV2.Envelope envelope = NativePolicyExporter.issueApproved(issuer, payload,
                Base64.getDecoder().decode(challenge.required("supervisorSignature").asText()),
                Base64.getDecoder().decode(approval.required("operatorSignature").asText()), node::sign, boottime());
        consumed.add(payload.issuanceId());
        byte[] result = JSON.writeValueAsBytes(Map.of("envelope", envelope));
        Path temporary = Files.createTempFile(directory, ".signed-", ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(result);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            Files.move(temporary, directory.resolve("inbox.json"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(temporary); }
        return true;
    }

    private static Set<String> fields(JsonNode node) {
        Set<String> result = new HashSet<>(); node.fieldNames().forEachRemaining(result::add); return result;
    }
}
