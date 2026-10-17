package com.defenderlink.mesh.ledger.store;

import com.defenderlink.mesh.identity.NodeIdentity;
import com.defenderlink.mesh.ledger.model.Block;
import com.defenderlink.mesh.ledger.model.LedgerEntry;
import com.defenderlink.mesh.ledger.model.LedgerEntry.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.rocksdb.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Persistent ledger storage using RocksDB.
 *
 * Two logical stores:
 * 1. CHAIN: Append-only block storage (block:0, block:1, ...)
 * 2. STATE: Materialized view of current network state, derived from chain
 *    - Registered nodes and their endpoints
 *    - Active services and their access policies
 *
 * The STATE is rebuilt from CHAIN on startup (crash recovery).
 * All reads go to STATE (fast ConcurrentHashMap lookups).
 * All writes go through the chain (append block → update state).
 */
@ApplicationScoped
public class LedgerStore {

    private static final Logger log = LoggerFactory.getLogger(LedgerStore.class);

    @ConfigProperty(name = "mesh.ledger.data-dir")
    String ledgerDataDir;

    @ConfigProperty(name = "mesh.license.key")
    Optional<String> licenseKey;

    @ConfigProperty(name = "mesh.node.max-free", defaultValue = "3")
    int maxFreeNodes;

    @ConfigProperty(name = "mesh.node.max-pro", defaultValue = "25")
    int maxProNodes;

    @Inject
    NodeIdentity identity;

    private RocksDB db;
    private final ObjectMapper mapper;
    private final ReentrantReadWriteLock chainLock = new ReentrantReadWriteLock();

    // Materialized state (rebuilt from chain)
    private final Map<String, NodeRecord> nodes = new ConcurrentHashMap<>();
    private final Map<String, ServiceRecord> services = new ConcurrentHashMap<>();
    private Block lastBlock;
    private long chainHeight = -1;

    public LedgerStore() {
        mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
    }

    void onStart(@Observes StartupEvent ev) {
        try {
            RocksDB.loadLibrary();
            Path dbPath = Path.of(ledgerDataDir);
            Files.createDirectories(dbPath);

            Options opts = new Options().setCreateIfMissing(true)
                    .setWriteBufferSize(16 * 1024 * 1024);
            db = RocksDB.open(opts, dbPath.toString());

            rebuildState();
            log.info("Ledger initialized: height={}, nodes={}, services={}",
                    chainHeight, nodes.size(), services.size());
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize ledger store", e);
        }
    }

    void onStop(@Observes ShutdownEvent ev) {
        if (db != null) db.close();
    }

    // =========================================================================
    // Chain Operations
    // =========================================================================

    /** Append a new block to the chain */
    public Block appendBlock(List<LedgerEntry> entries) {
        chainLock.writeLock().lock();
        try {
            long newIndex = chainHeight + 1;
            String prevHash = lastBlock != null ? lastBlock.hash() : Block.genesis().hash();
            String merkleRoot = Block.computeMerkleRoot(entries);
            Instant now = Instant.now();

            String hash = Block.computeHash(newIndex, prevHash, merkleRoot,
                    identity.getNodeId(), now, entries);

            byte[] signable = (newIndex + prevHash + merkleRoot +
                    identity.getNodeId() + now.toEpochMilli())
                    .getBytes(StandardCharsets.UTF_8);
            byte[] signature = identity.sign(signable);

            Block block = new Block(newIndex, hash, prevHash, merkleRoot,
                    identity.getNodeId(), signature, entries, now);

            // Persist
            byte[] key = ("block:" + newIndex).getBytes(StandardCharsets.UTF_8);
            db.put(key, mapper.writeValueAsBytes(block));

            // Update state
            applyBlock(block);
            lastBlock = block;
            chainHeight = newIndex;

            log.info("Block {} appended: {} entries, hash={}",
                    newIndex, entries.size(), hash.substring(0, 16));
            return block;

        } catch (Exception e) {
            throw new RuntimeException("Failed to append block", e);
        } finally {
            chainLock.writeLock().unlock();
        }
    }

    /** Accept a block from a remote peer (Raft replication) */
    public boolean acceptBlock(Block block) {
        chainLock.writeLock().lock();
        try {
            // Validate chain continuity
            if (block.index() != chainHeight + 1) {
                log.warn("Block {} out of order (expected {})", block.index(), chainHeight + 1);
                return false;
            }
            if (!block.isHashValid()) {
                log.warn("Block {} has invalid hash", block.index());
                return false;
            }
            if (lastBlock != null && !block.isChainedTo(lastBlock)) {
                log.warn("Block {} not chained to previous", block.index());
                return false;
            }

            // Validate author signature
            byte[] signable = block.getSignableBytes();
            byte[] authorPubKey = HexFormat.of().parseHex(block.authorNodeId());
            if (!NodeIdentity.verify(signable, block.authorSignature(), authorPubKey)) {
                // Allow genesis block or known nodes
                if (block.index() > 0 && !block.authorNodeId().equals("genesis")) {
                    log.warn("Block {} has invalid author signature", block.index());
                    return false;
                }
            }

            // Persist and apply
            byte[] key = ("block:" + block.index()).getBytes(StandardCharsets.UTF_8);
            db.put(key, mapper.writeValueAsBytes(block));

            applyBlock(block);
            lastBlock = block;
            chainHeight = block.index();
            return true;

        } catch (Exception e) {
            log.error("Failed to accept block {}", block.index(), e);
            return false;
        } finally {
            chainLock.writeLock().unlock();
        }
    }

    /** Get a block by index */
    public Optional<Block> getBlock(long index) {
        try {
            byte[] key = ("block:" + index).getBytes(StandardCharsets.UTF_8);
            byte[] data = db.get(key);
            if (data == null) return Optional.empty();
            return Optional.of(mapper.readValue(data, Block.class));
        } catch (Exception e) {
            throw new RuntimeException("Failed to read block " + index, e);
        }
    }

    public long getChainHeight() { return chainHeight; }
    public Block getLastBlock() { return lastBlock; }

    // =========================================================================
    // State Queries (fast, from materialized view)
    // =========================================================================

    /** Get all registered nodes */
    public Collection<NodeRecord> getNodes() {
        return nodes.values();
    }

    /** Get a specific node */
    public Optional<NodeRecord> getNode(String nodeId) {
        return Optional.ofNullable(nodes.get(nodeId));
    }

    /** Get all active services */
    public Collection<ServiceRecord> getServices() {
        return services.values();
    }

    /** Get services this node is allowed to access */
    public List<ServiceRecord> getServicesForNode(String nodeId) {
        return services.values().stream()
                .filter(s -> s.allowedNodes.contains(nodeId))
                .toList();
    }

    /** Get a specific service */
    public Optional<ServiceRecord> getService(String serviceId) {
        return Optional.ofNullable(services.get(serviceId));
    }

    /** Get services exposed by a specific node */
    public List<ServiceRecord> getServicesByOwner(String nodeId) {
        return services.values().stream()
                .filter(s -> s.ownerNodeId.equals(nodeId))
                .toList();
    }

    private void validateNodeLimit() {
        String key = licenseKey == null ? "" : licenseKey.orElse("");
        boolean isFree       = key.isBlank();
        boolean isPro        = !isFree && key.startsWith("dl_pro_");
        boolean isEnterprise = !isFree && key.startsWith("dl_ent_");

        if (isEnterprise) return; // unlimited

        long activeNodes = nodes.values().stream().filter(NodeRecord::active).count();

        if (isFree && activeNodes >= maxFreeNodes) {
            throw new LicenseLimitException(
                    "Free tier is limited to " + maxFreeNodes + " nodes. " +
                            "Upgrade at https://defenderlink.io/pricing"
            );
        }
        if (isPro && activeNodes >= maxProNodes) {
            throw new LicenseLimitException(
                    "Pro tier is limited to " + maxProNodes + " nodes. " +
                            "Contact sales@wpotech.com for Enterprise."
            );
        }
    }

    // =========================================================================
    // State Materialization
    // =========================================================================

    private void applyBlock(Block block) {
        for (LedgerEntry entry : block.entries()) {
            switch (entry) {
                case NodeRegister nr -> {
                    // Only check limit for genuinely new nodes
                    if (!nodes.containsKey(nr.authorNodeId())) {
                        validateNodeLimit();
                    }
                    nodes.put(nr.authorNodeId(), new NodeRecord(
                            nr.authorNodeId(), nr.wireguardPubkey(), nr.endpoints(),
                            nr.capabilities(), nr.displayName(), nr.timestamp(), true));
                }

                case NodeDeregister nd -> nodes.computeIfPresent(nd.authorNodeId(),
                        (k, v) -> v.withActive(false));

                case NodeUpdate nu -> nodes.computeIfPresent(nu.authorNodeId(),
                        (k, v) -> v.withEndpoints(nu.endpoints())
                                .withCapabilities(nu.capabilities()));

                case ServiceExpose se -> services.put(se.serviceId(), new ServiceRecord(
                        se.serviceId(), se.authorNodeId(), se.protocol(), se.localBind(),
                        se.assignedPort(), se.allowedNodes(), se.policy(), se.timestamp(), true));

                case ServiceRevoke sr -> services.computeIfPresent(sr.serviceId(),
                        (k, v) -> v.withActive(false));

                case ServiceUpdate su -> services.computeIfPresent(su.serviceId(),
                        (k, v) -> v.withAllowedNodes(su.allowedNodes()).withPolicy(su.policy()));
            }
        }
    }

    private void rebuildState() {
        nodes.clear();
        services.clear();

        // Check for genesis
        try {
            byte[] genesisData = db.get("block:0".getBytes(StandardCharsets.UTF_8));
            if (genesisData == null) {
                Block genesis = Block.genesis();
                db.put("block:0".getBytes(StandardCharsets.UTF_8),
                        mapper.writeValueAsBytes(genesis));
                lastBlock = genesis;
                chainHeight = 0;
                log.info("Genesis block created");
                return;
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to check genesis block", e);
        }

        // Replay all blocks
        long idx = 0;
        while (true) {
            Optional<Block> block = getBlock(idx);
            if (block.isEmpty()) break;
            applyBlock(block.get());
            lastBlock = block.get();
            chainHeight = idx;
            idx++;
        }
    }

    // =========================================================================
    // Materialized State Records
    // =========================================================================

    public record NodeRecord(
            String nodeId, String wireguardPubkey, List<String> endpoints,
            List<String> capabilities, String displayName, Instant registeredAt, boolean active
    ) {
        public NodeRecord withActive(boolean a) {
            return new NodeRecord(nodeId, wireguardPubkey, endpoints, capabilities, displayName, registeredAt, a);
        }
        public NodeRecord withEndpoints(List<String> ep) {
            return new NodeRecord(nodeId, wireguardPubkey, ep, capabilities, displayName, registeredAt, active);
        }
        public NodeRecord withCapabilities(List<String> cap) {
            return new NodeRecord(nodeId, wireguardPubkey, endpoints, cap, displayName, registeredAt, active);
        }
    }

    public record ServiceRecord(
            String serviceId, String ownerNodeId, String protocol, String localBind,
            int assignedPort, List<String> allowedNodes, LedgerEntry.ServicePolicy policy,
            Instant exposedAt, boolean active
    ) {
        public ServiceRecord withActive(boolean a) {
            return new ServiceRecord(serviceId, ownerNodeId, protocol, localBind, assignedPort, allowedNodes, policy, exposedAt, a);
        }
        public ServiceRecord withAllowedNodes(List<String> an) {
            return new ServiceRecord(serviceId, ownerNodeId, protocol, localBind, assignedPort, an, policy, exposedAt, active);
        }
        public ServiceRecord withPolicy(LedgerEntry.ServicePolicy p) {
            return new ServiceRecord(serviceId, ownerNodeId, protocol, localBind, assignedPort, allowedNodes, p, exposedAt, active);
        }
    }
}
