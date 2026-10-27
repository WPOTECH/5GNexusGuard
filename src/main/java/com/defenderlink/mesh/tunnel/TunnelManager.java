package com.defenderlink.mesh.tunnel;

import com.defenderlink.mesh.identity.NodeIdentity;
import com.defenderlink.mesh.ledger.store.LedgerStore;
import com.defenderlink.mesh.ledger.store.LedgerStore.NodeRecord;
import com.defenderlink.mesh.ledger.store.LedgerStore.ServiceRecord;
import com.defenderlink.mesh.proxy.EgressProxy;
import com.defenderlink.mesh.proxy.InterceptProxy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Per-service WireGuard tunnel manager.
 *
 * Each service gets its own:
 * - WireGuard interface (dl-svc-postgres, dl-svc-redis, etc.)
 * - Keypair (separate from node identity)
 * - Subnet (/30 point-to-point)
 * - Configuration
 *
 * Tunnels are created on-demand when a local intercept proxy needs to
 * reach a remote service. The tunnel manager queries the ledger for
 * the remote node's WireGuard public key and endpoint — no key exchange
 * protocol needed because the ledger already has all keys.
 *
 * ZTA principle: one tunnel per service, full isolation.
 */
@ApplicationScoped
public class TunnelManager {

    private static final Logger log = LoggerFactory.getLogger(TunnelManager.class);

    @ConfigProperty(name = "mesh.tunnel.interface-prefix", defaultValue = "dl")
    String ifPrefix;

    @ConfigProperty(name = "mesh.tunnel.subnet-prefix", defaultValue = "10.200")
    String subnetPrefix;

    @ConfigProperty(name = "mesh.tunnel.listen-port-start", defaultValue = "51820")
    int listenPortStart;

    @ConfigProperty(name = "mesh.tunnel.mtu", defaultValue = "1420")
    int mtu;

    @ConfigProperty(name = "mesh.tunnel.keepalive", defaultValue = "25")
    int keepalive;

    @ConfigProperty(name = "mesh.data-dir")
    String dataDir;

    // Optional confined WireGuard config location; default preserves existing storage.
    @ConfigProperty(name = "mesh.tunnel.config-dir")
    Optional<String> configDirOverride;

    @Inject
    com.defenderlink.mesh.tunnel.nativeaccess.AccessMode accessMode;

    @Inject
    NodeIdentity identity;

    @Inject
    LedgerStore ledger;

    @Inject
    EgressProxy egressProxy;      // ADD THIS

    @Inject
    InterceptProxy interceptProxy; // ADD THIS

    @Inject
    com.fasterxml.jackson.databind.ObjectMapper objectMapper; // ADD THIS

    @ConfigProperty(name = "mesh.tunnel.egress-port-start", defaultValue = "15100")
    int egressPortStart;

    @ConfigProperty(name = "mesh.node.public-endpoint", defaultValue = "127.0.0.1:51820")
    String publicEndpoint;

    private final Map<String, ActiveTunnel> tunnels = new ConcurrentHashMap<>();
    final String interfaceOwner = "5gnexus-" + java.util.UUID.randomUUID();
    final Map<String, Integer> ownedInterfaces = new ConcurrentHashMap<>();
    private final AtomicInteger subnetCounter = new AtomicInteger(1);
    private final AtomicInteger portCounter = new AtomicInteger(0);

    /**
     * Ensure a tunnel exists to reach the given service.
     * If tunnel already exists, returns it. Otherwise creates a new one.
     *
     * This is the key simplification vs. DefenderLink v1:
     * NO mTLS key exchange needed. The ledger already has the remote node's
     * WireGuard public key. We just configure WireGuard directly.
     */

    public synchronized ActiveTunnel ensureTunnel(String serviceId) throws Exception {
        accessMode.requireStandard();
        String connKey = "conn:" + serviceId;
        ActiveTunnel existing = tunnels.get(connKey);
        if (existing != null && existing.isUp()) return existing;
        if (existing != null) throw new IllegalStateException("Previous tunnel cleanup remains pending");

        LedgerStore.ServiceRecord svc = ledger.getService(serviceId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown service: " + serviceId));
        LedgerStore.NodeRecord ownerNode = ledger.getNode(svc.ownerNodeId())
                .orElseThrow(() -> new IllegalStateException("Owner node not in ledger"));

        // Generate this node's per-service WG keypair and claim .1 address
        String[] kp        = generateWgKeyPair();
        String localPrivKey = kp[0];
        String localPubKey  = kp[1];

        int subnet      = subnetCounter.getAndIncrement();
        String localIp  = subnetPrefix + "." + subnet + ".1/30";
        int port        = listenPortStart + portCounter.getAndIncrement();
        String ifName   = interfaceName(ifPrefix, "c", serviceId, identity.getNodeId(), svc.ownerNodeId());

        // Sign the negotiate payload
        String signable = serviceId + identity.getNodeId() + localPubKey;
        log.info("DEBUG sign: signable='{}' nodeId='{}' wgPubkey='{}'",
                signable, identity.getNodeId(), localPubKey);
        String sig = java.util.Base64.getEncoder()
                .encodeToString(identity.sign(signable.getBytes()));
        log.info("DEBUG sig='{}'", sig);

        // Call the owner node — it creates its interface + egress and returns its pubkey
        String ownerBaseUrl = "http://" + ownerNode.endpoints().get(0).split(":")[0] + ":8443";
        TunnelNegotiationResource.NegotiateRequest negotiateReq =
                new TunnelNegotiationResource.NegotiateRequest(
                        serviceId,
                        identity.getNodeId(),
                        localPubKey,
                        localIp,
                        advertisedEndpoint(publicEndpoint, listenPortStart, port),
                        sig
                );
        TunnelNegotiationResource.NegotiateResponse negotiateResp =
                callNegotiateEndpoint(ownerBaseUrl, negotiateReq);

        log.info("Negotiate OK: ownerPubkey={} ownerIp={} egressPort={}",
                negotiateResp.ownerWgPubkey(),
                negotiateResp.ownerTunnelIp(),
                negotiateResp.egressPort());

        // Bring up the connector-side WireGuard interface
        String ownerTunnelIpOnly = negotiateResp.ownerTunnelIp().split("/")[0];
        String ownerEndpoint = validatedEndpoint(negotiateResp.ownerEndpoint());
        createOwnedInterface(ifName);
        String configPath = writeConfig(ifName, localPrivKey, port,
                negotiateResp.ownerWgPubkey(), ownerEndpoint, ownerTunnelIpOnly);
        exec("ip", "addr", "add", localIp, "dev", ifName);
        exec("ip", "link", "set", "mtu", String.valueOf(mtu), "dev", ifName);
        exec("ip", "link", "set", "up", "dev", ifName);
        exec("/usr/bin/wg", "setconf", ifName, configPath);

        // Track the tunnel
        ActiveTunnel at = new ActiveTunnel(serviceId, ifName, localIp,
                localPubKey, port, svc.ownerNodeId(), TunnelRole.CONNECTOR,
                negotiateResp.egressPort());
        at.setPeerTunnelIp(ownerTunnelIpOnly);
        tunnels.put(connKey, at);

        // Start the intercept proxy — now callers can connect to 127.0.0.1:localPort
        int localProxyPort = interceptProxy.startIntercept(
                serviceId, ownerTunnelIpOnly, negotiateResp.egressPort());
        at.setInterceptLocalPort(localProxyPort);

        log.info("Tunnel ready: svc='{}' → 127.0.0.1:{}", serviceId, localProxyPort);
        return at;
    }

    /**
     * Tear down a specific service tunnel.
     */
    public synchronized void destroyTunnel(String serviceId) {
        ActiveTunnel tunnel = tunnels.get("conn:" + serviceId);
        if (tunnel == null) return;

        try {
            deleteOwnedInterface(tunnel.ifName);
            tunnels.remove("conn:" + serviceId, tunnel);
            log.info("Destroyed tunnel {} for service '{}'", tunnel.ifName, serviceId);
        } catch (Exception e) {
            tunnel.setState(TunnelState.FAILED);
            tunnel.setError("Owned interface cleanup pending");
            log.warn("Failed to clean up owned tunnel {}; retaining failed tracking", tunnel.ifName);
        }
    }

    private final java.util.concurrent.atomic.AtomicInteger egressPortCounter =
            new java.util.concurrent.atomic.AtomicInteger(0);

    private final java.net.http.HttpClient httpClient =
            java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(8))
                    .build();


// =========================================================================
// Owner-side tunnel creation (called via TunnelNegotiationResource)
// =========================================================================

    public synchronized ReciprocatedTunnel createOwnerSideTunnel(
            String serviceId,
            String initiatorNodeId,
            String initiatorWgPubkey,
            String initiatorTunnelIp,   // e.g. "10.200.1.1/30"
            String initiatorEndpoint    // e.g. "192.168.5.104:51821"
    ) throws Exception {

        accessMode.requireStandard();
        String ownerKey = "owner:" + serviceId + ":" + initiatorNodeId;
        ActiveTunnel existing = tunnels.get(ownerKey);
        if (existing != null) {
            if (!existing.isUp()) throw new IllegalStateException("Previous owner tunnel cleanup remains pending");
            log.info("Owner-side tunnel already exists for svc='{}', reusing", serviceId);
            return new ReciprocatedTunnel(existing.ifName, existing.localPublicKey,
                    existing.localIp, existing.listenPort, existing.egressPort());
        }

        // Owner takes .2; initiator holds .1
        String ownerTunnelIp = deriveOwnerIp(initiatorTunnelIp);
        String tunnelIpOnly  = ownerTunnelIp.split("/")[0];

        // Generate per-service WireGuard keypair
        String[] kp         = generateWgKeyPair();
        String privateKey   = kp[0];
        String publicKey    = kp[1];

        int port   = listenPortStart + portCounter.getAndIncrement();
        String ifName = interfaceName(ifPrefix, "o", serviceId, identity.getNodeId(), initiatorNodeId);

        // Write wg config and bring up interface
        String initiatorTunnelIpOnly = initiatorTunnelIp.split("/")[0];
        createOwnedInterface(ifName);
        String configPath = writeConfig(ifName, privateKey, port,
                initiatorWgPubkey, initiatorEndpoint, initiatorTunnelIpOnly);
        exec("ip", "addr", "add", ownerTunnelIp, "dev", ifName);
        exec("ip", "link", "set", "mtu", String.valueOf(mtu), "dev", ifName);
        exec("ip", "link", "set", "up", "dev", ifName);
        exec("/usr/bin/wg", "setconf", ifName, configPath);

        // Look up what service port to forward to
        LedgerStore.ServiceRecord svc = ledger.getService(serviceId)
                .orElseThrow(() -> new IllegalStateException("Service not found: " + serviceId));
        String[] bindParts = svc.localBind().split(":");
        String svcHost = bindParts.length > 1 ? bindParts[0] : "127.0.0.1";
        int svcPort    = Integer.parseInt(bindParts[bindParts.length - 1]);

        // Start egress proxy bound to the tunnel interface IP
        int egressPort = egressPortStart + egressPortCounter.getAndIncrement();
        egressProxy.startEgressOnInterface(tunnelIpOnly, egressPort, svcHost, svcPort, serviceId);

        ActiveTunnel at = new ActiveTunnel(serviceId, ifName, ownerTunnelIp,
                publicKey, port, initiatorNodeId, TunnelRole.OWNER, egressPort);
        tunnels.put(ownerKey, at);

        log.info("Owner-side tunnel up: if={} ip={} egressPort={}", ifName, ownerTunnelIp, egressPort);
        return new ReciprocatedTunnel(ifName, publicKey, ownerTunnelIp, port, egressPort);
    }

    public synchronized void destroyOwnerSideTunnel(String serviceId, String initiatorNodeId) {
        String ownerKey = "owner:" + serviceId + ":" + initiatorNodeId;
        ActiveTunnel at = tunnels.get(ownerKey);
        if (at == null) return;

        // Stop egress before removing the interface it's bound to
        String tunnelIpOnly = at.localIp.split("/")[0];
        egressProxy.stopEgressOnInterface(serviceId, tunnelIpOnly);

        try {
            deleteOwnedInterface(at.ifName);
            tunnels.remove(ownerKey, at);
            log.info("Destroyed owner-side tunnel: if={}", at.ifName);
        } catch (Exception e) {
            at.setState(TunnelState.FAILED);
            at.setError("Owned interface cleanup pending");
            log.warn("Interface removal failed for {}; retaining failed tracking", at.ifName);
        }
    }

// =========================================================================
// Connector-side tunnel creation (called from ensureTunnel)
// =========================================================================

    /**
     * Look up a live connector-side tunnel for the status API / intercept proxy.
     */
    public java.util.Optional<ActiveTunnel> getActiveTunnel(String serviceId) {
        ActiveTunnel at = tunnels.get("conn:" + serviceId);
        if (at == null || !at.isUp()) return java.util.Optional.empty();
        return java.util.Optional.of(at);
    }

// =========================================================================
// Helpers
// =========================================================================

    /**
     * Initiator claims x.x.x.1/30 → owner takes x.x.x.2/30
     */
    private String deriveOwnerIp(String initiatorCidr) {
        String[] parts  = initiatorCidr.split("/");
        String[] octets = parts[0].split("\\.");
        int last = Integer.parseInt(octets[3]);
        octets[3] = String.valueOf(last == 1 ? 2 : 1);
        return String.join(".", octets) + "/30";
    }

    static String advertisedEndpoint(String configuredEndpoint, int firstListenPort, int listenPort) {
        if (firstListenPort < 1 || firstListenPort > 65535 || listenPort < firstListenPort || listenPort > 65535)
            throw new IllegalArgumentException("Invalid WireGuard endpoint or allocated port");
        java.net.URI endpoint = endpointUri(configuredEndpoint);
        long advertisedPort = (long) endpoint.getPort() + listenPort - firstListenPort;
        if (advertisedPort > 65535) throw new IllegalArgumentException("Advertised WireGuard port range exhausted");
        // Preserve an explicitly mapped first public port. Further services use
        // a contiguous advertised range; forwarding that range is operator-owned.
        return configuredEndpoint.substring(0, configuredEndpoint.lastIndexOf(':') + 1) + advertisedPort;
    }

    static String validatedEndpoint(String advertisedEndpoint) {
        endpointUri(advertisedEndpoint);
        return advertisedEndpoint; // Owner's advertised (possibly mapped) port is authoritative.
    }

    private static java.net.URI endpointUri(String configuredEndpoint) {
        if (configuredEndpoint == null) throw new IllegalArgumentException("Explicit WireGuard endpoint required");
        final java.net.URI endpoint;
        try { endpoint = java.net.URI.create("udp://" + configuredEndpoint); }
        catch (IllegalArgumentException invalid) { throw new IllegalArgumentException("Invalid WireGuard endpoint"); }
        if (endpoint.getHost() == null || endpoint.getPort() < 1 || endpoint.getPort() > 65535
                || endpoint.getRawUserInfo() != null || !endpoint.getRawPath().isEmpty()
                || endpoint.getRawQuery() != null || endpoint.getRawFragment() != null)
            throw new IllegalArgumentException("Explicit WireGuard host and port required");
        return endpoint;
    }

    static String interfaceName(String prefix, String role, String service, String localNode, String peerNode) {
        if (prefix == null || !prefix.matches("[A-Za-z][A-Za-z0-9]{0,3}")
                || !("c".equals(role) || "o".equals(role)))
            throw new IllegalArgumentException("Invalid WireGuard interface prefix or role");
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(
                    (role + "\0" + service + "\0" + localNode + "\0" + peerNode)
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return prefix + "-" + role + "-" + java.util.HexFormat.of().formatHex(digest).substring(0, 12-prefix.length());
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    void createOwnedInterface(String name) throws Exception {
        // Kernel EEXIST is a hard failure. Never delete/adopt a pre-existing name.
        exec("ip", "link", "add", "dev", name, "type", "wireguard");
        exec("ip", "link", "set", "dev", name, "alias", interfaceOwner);
        var info = linkInfo(name);
        if (info == null || !info.path("ifindex").isInt() || info.path("ifindex").asInt()<=0
                || !interfaceOwner.equals(info.path("ifalias").asText()))
            throw new IllegalStateException("Unable to establish interface ownership");
        ownedInterfaces.put(name, info.path("ifindex").asInt());
    }

    private com.fasterxml.jackson.databind.JsonNode linkInfo(String name) throws Exception {
        var rows = new com.fasterxml.jackson.databind.ObjectMapper().readTree(execCapture("ip", "-j", "link", "show"));
        if (!rows.isArray()) throw new IllegalStateException("Invalid kernel link response");
        for (var row : rows) if (name.equals(row.path("ifname").asText())) return row;
        return null;
    }

    void deleteOwnedInterface(String name) throws Exception {
        var info = linkInfo(name);
        if (info == null) { ownedInterfaces.remove(name); return; }
        Integer index = ownedInterfaces.get(name);
        if (index == null || index != info.path("ifindex").asInt()
                || !interfaceOwner.equals(info.path("ifalias").asText()))
            throw new IllegalStateException("Interface ownership changed; refusing deletion");
        exec("ip", "link", "delete", "dev", name);
        ownedInterfaces.remove(name);
    }

    @jakarta.annotation.PreDestroy
    void shutdownOwnedTunnels() {
        for (ActiveTunnel tunnel : java.util.List.copyOf(tunnels.values())) {
            if (tunnel.role == TunnelRole.CONNECTOR) {
                interceptProxy.stopIntercept(tunnel.serviceId);
                destroyTunnel(tunnel.serviceId);
            } else destroyOwnerSideTunnel(tunnel.serviceId, tunnel.peerNodeId);
        }
    }

    /**
     * HTTP call to the owner node's /internal/tunnel/negotiate endpoint.
     */
    private TunnelNegotiationResource.NegotiateResponse callNegotiateEndpoint(
            String ownerBaseUrl,
            TunnelNegotiationResource.NegotiateRequest req) throws Exception {

        String body = objectMapper.writeValueAsString(req);
        var httpReq = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(ownerBaseUrl + "/internal/tunnel/negotiate"))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                .timeout(java.time.Duration.ofSeconds(10))
                .build();

        var resp = httpClient.send(httpReq,
                java.net.http.HttpResponse.BodyHandlers.ofString());

        if (resp.statusCode() != 200) {
            throw new RuntimeException("Negotiate HTTP " + resp.statusCode() + ": " + resp.body());
        }
        return objectMapper.readValue(resp.body(),
                TunnelNegotiationResource.NegotiateResponse.class);
    }


    /** Get all active tunnels */
    public Map<String, ActiveTunnel> getActiveTunnels() {
        return Map.copyOf(tunnels);
    }

    // =========================================================================
    // Tunnel Creation
    // =========================================================================


    private String writeConfig(String ifName, String privKey, int listenPort,
                                String peerPubKey, String endpoint,
                                String allowedIp) throws Exception {
        String configured = configDirOverride.orElse(dataDir + "/wg-configs");
        Path directory = Path.of(configured);
        if (!directory.isAbsolute() || !ifName.matches("[A-Za-z0-9_-]{1,15}"))
            throw new IllegalArgumentException("Invalid WireGuard config path or interface");
        directory = directory.normalize();
        // A directory beneath a replaceable ancestor cannot be trusted after
        // validation. A sticky root-owned /tmp is safe against another UID
        // replacing our owned child; an ordinary world-writable parent is not.
        Path ancestor = directory.getRoot();
        long fsUid = -1;
        for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
            if (line.startsWith("Uid:")) {
                String[] ids = line.trim().split("\\s+");
                if (ids.length == 5) fsUid = Long.parseLong(ids[4]);
                break;
            }
        }
        if (fsUid < 0) throw new IllegalStateException("Cannot establish process file-system UID");
        for (Path component : directory) {
            if (Files.exists(ancestor, LinkOption.NOFOLLOW_LINKS)) {
                if (!Files.isDirectory(ancestor, LinkOption.NOFOLLOW_LINKS))
                    throw new IllegalStateException("WireGuard config ancestor is not a real directory");
                var permissions = Files.getPosixFilePermissions(ancestor, LinkOption.NOFOLLOW_LINKS);
                boolean sharedWrite = permissions.contains(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE)
                        || permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
                int mode = (int) Files.getAttribute(ancestor, "unix:mode", LinkOption.NOFOLLOW_LINKS);
                long ownerUid = ((Number) Files.getAttribute(ancestor, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue();
                if ((ownerUid != 0 && ownerUid != fsUid)
                        || (sharedWrite && ((mode & 01000) == 0 || ownerUid != 0)))
                    throw new IllegalStateException("WireGuard config ancestor is replaceable");
            }
            ancestor = ancestor.resolve(component);
        }
        Files.createDirectories(directory,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        if (!directory.toRealPath().equals(directory)
                || ((Number) Files.getAttribute(directory, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue() != fsUid)
            throw new IllegalStateException("WireGuard config directory must be real and owned by this process");
        // Legacy default directories were made by mkdirs() under the caller's
        // umask (often 0755). Tighten only an owned default directory before
        // writing; explicit confined overrides must already be provisioned.
        if (configDirOverride.isEmpty())
            Files.setPosixFilePermissions(directory,
                    PosixFilePermissions.fromString("rwx------"));
        if (!Files.getPosixFilePermissions(directory).equals(PosixFilePermissions.fromString("rwx------")))
            throw new IllegalStateException("WireGuard config directory must be private");
        Path path = directory.resolve(ifName + ".conf");

        String config = "[Interface]\nPrivateKey = " + privKey +
                "\nListenPort = " + listenPort +
                "\n\n[Peer]\nPublicKey = " + peerPubKey +
                "\nEndpoint = " + endpoint +
                "\nAllowedIPs = " + allowedIp + "/32" +
                "\nPersistentKeepalive = " + keepalive + "\n";

        Path temporary = Files.createTempFile(directory, ".wg-", ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            if (!Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS)
                    .equals(Files.getOwner(temporary, LinkOption.NOFOLLOW_LINKS)))
                throw new IllegalStateException("WireGuard config directory must belong to this process");
            // Reopening with NOFOLLOW prevents an exchanged temporary symlink
            // from redirecting the private key to a different file.
            try (var output = Files.newOutputStream(temporary,
                    java.nio.file.StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                output.write(config.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temporary);
        }
        return path.toString();
    }

    private String[] generateWgKeyPair() throws Exception {
        // Use wg genkey/pubkey if available, otherwise BouncyCastle X25519
        try {
            String privKey = execCapture("/usr/bin/wg", "genkey").trim();
            String pubKey = execCaptureWithInput(privKey + "\n", "/usr/bin/wg", "pubkey").trim();
            return new String[]{privKey, pubKey};
        } catch (Exception e) {
            // Fallback: BouncyCastle X25519 (same as KeyManager in v1)
            var kpg = java.security.KeyPairGenerator.getInstance("X25519", "BC");
            var kp = kpg.generateKeyPair();
            byte[] priv = kp.getPrivate().getEncoded();
            byte[] pub = kp.getPublic().getEncoded();
            byte[] rawPriv = new byte[32]; byte[] rawPub = new byte[32];
            System.arraycopy(priv, priv.length - 32, rawPriv, 0, 32);
            System.arraycopy(pub, pub.length - 32, rawPub, 0, 32);
            return new String[]{
                    java.util.Base64.getEncoder().encodeToString(rawPriv),
                    java.util.Base64.getEncoder().encodeToString(rawPub)
            };
        }
    }

    void exec(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) throw new RuntimeException(String.join(" ", cmd) + ": " + out);
    }

    String execCapture(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        if (p.waitFor() != 0) throw new IllegalStateException("WireGuard key command failed");
        return output;
    }

    private String execCaptureWithInput(String input, String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        try (var stream = p.getOutputStream()) {
            stream.write(input.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }
        String output = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        if (p.waitFor() != 0) throw new IllegalStateException("WireGuard key command failed");
        return output;
    }

    // =========================================================================
    // Tunnel Record
    // =========================================================================

// =========================================================================
// Enums and records
// =========================================================================

    public enum TunnelState { ACTIVE, PAUSED, FAILED }
    public enum TunnelRole  { CONNECTOR, OWNER }

    public record ReciprocatedTunnel(
            String ifName,
            String wgPubkey,
            String tunnelIp,
            int    listenPort,
            int    egressPort
    ) {}

    @com.fasterxml.jackson.annotation.JsonAutoDetect(fieldVisibility = com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.ANY)
    public static class ActiveTunnel {
        public final String     serviceId;
        public final String     ifName;
        public final String     localIp;          // this node's /30 tunnel IP
        public final String     localPublicKey;
        public final int        listenPort;
        public final String     peerNodeId;
        public final TunnelRole role;

        // Set after negotiate response / after intercept proxy starts
        private String  peerTunnelIp       = "";
        private int     egressPort         = 0;
        private int     interceptLocalPort = 0;
        private TunnelState state          = TunnelState.ACTIVE;
        private String  error              = null;

        public ActiveTunnel(String serviceId, String ifName, String localIp,
                            String localPublicKey, int listenPort,
                            String peerNodeId, TunnelRole role, int egressPort) {
            this.serviceId      = serviceId;
            this.ifName         = ifName;
            this.localIp        = localIp;
            this.localPublicKey = localPublicKey;
            this.listenPort     = listenPort;
            this.peerNodeId     = peerNodeId;
            this.role           = role;
            this.egressPort     = egressPort;
        }

        public String      peerTunnelIp()                     { return peerTunnelIp; }
        public void        setPeerTunnelIp(String ip)         { this.peerTunnelIp = ip; }
        public int         egressPort()                       { return egressPort; }
        public int         interceptLocalPort()               { return interceptLocalPort; }
        public void        setInterceptLocalPort(int p)       { this.interceptLocalPort = p; }
        public TunnelState state()                            { return state; }
        public void        setState(TunnelState s)            { this.state = s; }
        public String      error()                            { return error; }
        public void        setError(String e)                 { this.error = e; }
        public boolean     isUp()  { return state == TunnelState.ACTIVE; }
    }
}
