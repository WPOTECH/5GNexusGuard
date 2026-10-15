package com.defenderlink.mesh.tunnel.nativeaccess;

import com.defenderlink.mesh.identity.NodeIdentity;
import com.defenderlink.mesh.ledger.store.LedgerStore;
import com.defenderlink.mesh.ledger.store.LedgerStore.ServiceRecord;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.LoggerFactory;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Map;

/** Local enforcement adapter. The ledger remains the service policy authority. */
@ApplicationScoped
public class NativePolicyExporter {
    @Inject AccessMode mode;
    @Inject LedgerStore ledger;
    @Inject NodeIdentity identity;
    @Inject ObjectMapper mapper;
    @ConfigProperty(name = "mesh.native.service-id", defaultValue = "unconfigured") String serviceId;
    @ConfigProperty(name = "mesh.native.client-node-id", defaultValue = "unconfigured") String clientId;
    @ConfigProperty(name = "mesh.native.lease-file", defaultValue = "/run/defenderlink-native/lease.json") String leaseFile;

    public static boolean allows(ServiceRecord s, String owner, String client, Instant now,
                                 boolean ownerActive, boolean clientActive) {
        return s != null && s.active() && ownerActive && clientActive
                && owner.equals(s.ownerNodeId()) && "tcp".equals(s.protocol())
                && "10.80.0.2:8080".equals(s.localBind())
                && s.allowedNodes() != null && s.allowedNodes().contains(client)
                && s.policy() != null && s.policy().encrypted()
                && s.policy().maxBandwidth() == null && s.policy().maxConcurrentConns() == null
                && (s.policy().expiresAt() == null || s.policy().expiresAt().isAfter(now));
    }

    @Scheduled(every = "1s", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void refresh() {
        if (!mode.nativeDual()) return;
        Path temporary = null;
        try {
            String owner = identity.getNodeId();
            Instant now = Instant.now();
            ServiceRecord service = ledger.getService(serviceId).orElse(null);
            boolean allowed = allows(service, owner, clientId, now,
                    ledger.getNode(owner).map(LedgerStore.NodeRecord::active).orElse(false),
                    ledger.getNode(clientId).map(LedgerStore.NodeRecord::active).orElse(false));
            long until = now.toEpochMilli();
            if (allowed) {
                until += 3000;
                if (service.policy().expiresAt() != null)
                    until = Math.min(until, service.policy().expiresAt().toEpochMilli());
            }
            Path target = Path.of(leaseFile).toAbsolutePath().normalize();
            Path directory = target.getParent();
            if (!directory.toRealPath().equals(directory)
                    || !Files.getPosixFilePermissions(directory).equals(PosixFilePermissions.fromString("rwx------")))
                throw new IllegalStateException("Lease directory must be private and not symlinked");
            temporary = Files.createTempFile(directory, ".lease-", ".tmp",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            mapper.writeValue(temporary.toFile(), Map.of("version", 1, "serviceId", serviceId,
                    "clientNodeId", clientId, "ownerNodeId", owner, "allowed", allowed,
                    "expiresAtMs", until));
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            // Never include exported content, keys or untrusted exception messages.
            LoggerFactory.getLogger(getClass()).warn("Native policy export failed; existing lease will expire");
        } finally {
            if (temporary != null) try { Files.deleteIfExists(temporary); } catch (Exception ignored) { }
        }
    }
}
