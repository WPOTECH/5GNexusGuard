package com.defenderlink.mesh.tunnel.nativeaccess;

import com.defenderlink.mesh.ledger.model.LedgerEntry.ServicePolicy;
import com.defenderlink.mesh.ledger.store.LedgerStore;
import com.defenderlink.mesh.ledger.store.LedgerStore.ServiceRecord;
import com.defenderlink.mesh.identity.NodeIdentity;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class NativePolicyExporterTest {
    static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    ServiceRecord service(String owner, String protocol, String bind, List<String> clients,
                          ServicePolicy policy, boolean active) {
        return new ServiceRecord("svc", owner, protocol, bind, 15000, clients, policy, NOW, active);
    }
    ServiceRecord valid() {
        return service("owner", "tcp", "10.80.0.2:8080", List.of("client"), ServicePolicy.defaults(), true);
    }
    boolean allow(ServiceRecord s) { return NativePolicyExporter.allows(s, "owner", "client", NOW, true, true); }

    @Test void requiresActiveMembershipAndExactResource() {
        assertTrue(allow(valid()));
        assertFalse(allow(null));
        assertFalse(allow(valid().withActive(false)));
        assertFalse(allow(valid().withAllowedNodes(List.of())));
        assertFalse(allow(valid().withAllowedNodes(null)));
        assertFalse(allow(service("other", "tcp", "10.80.0.2:8080", List.of("client"), ServicePolicy.defaults(), true)));
        assertFalse(allow(service("owner", "udp", "10.80.0.2:8080", List.of("client"), ServicePolicy.defaults(), true)));
        assertFalse(allow(service("owner", "tcp", "127.0.0.1:8080", List.of("client"), ServicePolicy.defaults(), true)));
        assertFalse(NativePolicyExporter.allows(valid(), "owner", "client", NOW, false, true));
        assertFalse(NativePolicyExporter.allows(valid(), "owner", "client", NOW, true, false));
    }
    @Test void expiryAndUnsupportedConstraintsDeny() {
        for (ServicePolicy policy : Arrays.asList(null, new ServicePolicy(false, null, null, null),
                new ServicePolicy(true, "1mbps", null, null), new ServicePolicy(true, null, 1, null),
                new ServicePolicy(true, null, null, NOW), new ServicePolicy(true, null, null, NOW.minusSeconds(1)))) {
            assertFalse(allow(valid().withPolicy(policy)));
        }
        assertTrue(allow(valid().withPolicy(new ServicePolicy(true, null, null, NOW.plusSeconds(1)))));
    }
    @Test void modeIsExplicitAndNeverFallsBack() {
        AccessMode mode = new AccessMode();
        mode.mode = "STANDARD";
        assertFalse(mode.nativeDual());
        assertDoesNotThrow(mode::requireStandard);
        mode.mode = "NATIVE_DUAL";
        assertTrue(mode.nativeDual());
        assertThrows(IllegalStateException.class, mode::requireStandard);
        mode.mode = "native_dual";
        assertThrows(IllegalStateException.class, mode::nativeDual);
    }
    @Test void externalConfigurationCannotClaimLocalEnforcement(@TempDir Path directory) {
        AccessMode mode = new AccessMode();
        mode.mode = "NATIVE_DUAL";
        assertTrue(mode.exportsLease());
        mode.gateway = "EXTERNAL_CONFIG";
        assertFalse(mode.exportsLease());
        assertThrows(IllegalStateException.class, mode::requireStandard);
        NativePolicyExporter exporter = new NativePolicyExporter();
        exporter.mode = mode;
        exporter.leaseFile = directory.resolve("lease.json").toString();
        assertDoesNotThrow(exporter::refresh); // No ledger dependency: must not export.
        assertFalse(Files.exists(Path.of(exporter.leaseFile)));
        mode.gateway = "pfsense";
        assertThrows(IllegalStateException.class, mode::gatewayMode);
    }

    @Test void exporterUsesLedgerViewAndPublishesRevocation(@TempDir Path directory) throws Exception {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        var records = new HashMap<String, ServiceRecord>();
        records.put("svc", valid());
        NativePolicyExporter exporter = new NativePolicyExporter();
        exporter.mode = new AccessMode(); exporter.mode.mode = "NATIVE_DUAL";
        exporter.ledger = new LedgerStore() {
            @Override public Optional<ServiceRecord> getService(String id) { return Optional.ofNullable(records.get(id)); }
            @Override public Optional<NodeRecord> getNode(String id) {
                return Optional.of(new NodeRecord(id, "", List.of(), List.of(), "", NOW, true));
            }
        };
        exporter.identity = new NodeIdentity() { @Override public String getNodeId() { return "owner"; } };
        exporter.mapper = new ObjectMapper(); exporter.serviceId = "svc"; exporter.clientId = "client";
        Path target = directory.resolve("lease.json"); exporter.leaseFile = target.toString();
        exporter.refresh();
        var lease = exporter.mapper.readTree(target.toFile());
        assertTrue(lease.get("allowed").asBoolean());
        assertEquals(2, lease.get("version").asInt());
        assertEquals("IKEV2_ESP_WIREGUARD", lease.get("transport").asText());
        assertEquals("client", lease.get("clientNodeId").asText());
        assertTrue(lease.get("expiresAtMs").asLong() <= System.currentTimeMillis() + 3000);
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(target));
        records.put("svc", valid().withActive(false));
        exporter.refresh();
        assertFalse(exporter.mapper.readTree(target.toFile()).get("allowed").asBoolean());
        records.clear(); exporter.refresh();
        assertFalse(exporter.mapper.readTree(target.toFile()).get("allowed").asBoolean());
    }
    @Test void persistedLedgerChangesDriveExport(@TempDir Path directory) throws Exception {
        Path leases = Files.createDirectory(directory.resolve("leases"));
        Files.setPosixFilePermissions(leases, PosixFilePermissions.fromString("rwx------"));
        try (var fixture = new com.defenderlink.mesh.ledger.store.NativeLedgerFixture(directory.resolve("ledger"))) {
            String owner = fixture.identity.getNodeId();
            byte[] signature = new byte[0]; // Entry authentication is a known baseline gap; blocks are signed.
            fixture.store.appendBlock(List.of(
                    new com.defenderlink.mesh.ledger.model.LedgerEntry.NodeRegister(owner, "", List.of(), List.of(), "owner", NOW, signature),
                    new com.defenderlink.mesh.ledger.model.LedgerEntry.NodeRegister("client", "", List.of(), List.of(), "client", NOW, signature),
                    new com.defenderlink.mesh.ledger.model.LedgerEntry.ServiceExpose(owner, "svc", "tcp", "10.80.0.2:8080",
                            15000, List.of("client"), ServicePolicy.defaults(), NOW, signature)));
            NativePolicyExporter exporter = new NativePolicyExporter();
            exporter.mode = new AccessMode(); exporter.mode.mode = "NATIVE_DUAL";
            exporter.ledger = fixture.store; exporter.identity = fixture.identity;
            exporter.mapper = new ObjectMapper(); exporter.serviceId = "svc"; exporter.clientId = "client";
            Path target = leases.resolve("lease.json"); exporter.leaseFile = target.toString();
            exporter.refresh();
            assertTrue(exporter.mapper.readTree(target.toFile()).get("allowed").asBoolean());
            fixture.store.appendBlock(List.of(new com.defenderlink.mesh.ledger.model.LedgerEntry.ServiceUpdate(
                    owner, "svc", List.of(), ServicePolicy.defaults(), NOW, signature)));
            exporter.refresh();
            assertFalse(exporter.mapper.readTree(target.toFile()).get("allowed").asBoolean());
            fixture.store.appendBlock(List.of(new com.defenderlink.mesh.ledger.model.LedgerEntry.ServiceUpdate(
                    owner, "svc", List.of("client"), ServicePolicy.defaults(), NOW, signature)));
            exporter.refresh();
            assertTrue(exporter.mapper.readTree(target.toFile()).get("allowed").asBoolean());
            fixture.store.appendBlock(List.of(new com.defenderlink.mesh.ledger.model.LedgerEntry.ServiceRevoke(
                    owner, "svc", "test", NOW, signature)));
            exporter.refresh();
            assertFalse(exporter.mapper.readTree(target.toFile()).get("allowed").asBoolean());
            assertTrue(fixture.store.getBlock(4).isPresent());
        }
    }

    @Test void nativeModeBlocksLegacyNetworkEntryPointsBeforeSideEffects() throws Exception {
        AccessMode mode = new AccessMode(); mode.mode = "NATIVE_DUAL";
        var egress = new com.defenderlink.mesh.proxy.EgressProxy();
        var manager = new com.defenderlink.mesh.tunnel.TunnelManager();
        var resource = new com.defenderlink.mesh.api.MeshResource();
        for (Object component : List.of(egress, manager, resource)) {
            var field = component.getClass().getDeclaredField("accessMode");
            field.setAccessible(true); field.set(component, mode);
        }
        var scheduledSync = egress.getClass().getDeclaredMethod("syncEgressBindings");
        scheduledSync.setAccessible(true);
        assertDoesNotThrow(() -> scheduledSync.invoke(egress)); // No ledger injected: must return before lookup/bind.
        assertThrows(IllegalStateException.class, () -> egress.startEgressOnInterface("", 0, "", 0, "svc"));
        assertThrows(IllegalStateException.class, () -> manager.ensureTunnel("svc"));
        assertThrows(IllegalStateException.class, () -> manager.createOwnerSideTunnel("svc", "client", "", "", ""));
        assertEquals(409, resource.connectToService("svc").getStatus());
    }

}
