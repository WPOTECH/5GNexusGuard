package com.defenderlink.mesh.api;

import com.defenderlink.mesh.gossip.GossipService;
import com.defenderlink.mesh.identity.NodeIdentity;
import com.defenderlink.mesh.ledger.consensus.RaftConsensus;
import com.defenderlink.mesh.ledger.model.LedgerEntry;
import com.defenderlink.mesh.ledger.model.LedgerEntry.*;
import com.defenderlink.mesh.ledger.store.LedgerStore;
import com.defenderlink.mesh.ledger.store.LedgerStore.*;
import com.defenderlink.mesh.ledger.store.LicenseLimitException;
import com.defenderlink.mesh.proxy.InterceptProxy;
import com.defenderlink.mesh.service.ServiceRegistry;
import com.defenderlink.mesh.tunnel.TunnelManager;
import com.defenderlink.mesh.tunnel.TunnelManager.ActiveTunnel;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;

@Path("/api")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class MeshResource {

    @Inject com.defenderlink.mesh.tunnel.nativeaccess.AccessMode accessMode;

    @Inject NodeIdentity identity;
    @Inject LedgerStore ledger;
    @Inject RaftConsensus raft;
    @Inject GossipService gossip;
    @Inject ServiceRegistry registry;
    @Inject TunnelManager tunnelManager;
    @Inject InterceptProxy interceptProxy;

    private static final Logger log = LoggerFactory.getLogger(MeshResource.class);

    // =========================================================================
    // Node Identity & Status
    // =========================================================================

    @GET @Path("/status")
    public Map<String, Object> status() {
        return Map.of(
                "nodeId", identity.getNodeId(),
                "shortId", identity.shortId(),
                "raftState", raft.getState().name(),
                "raftTerm", raft.getCurrentTerm(),
                "leader", raft.getCurrentLeader() != null
                        ? raft.getCurrentLeader().substring(0, 16) : "none",
                "chainHeight", ledger.getChainHeight(),
                "knownPeers", gossip.getKnownPeers().size(),
                "registeredNodes", ledger.getNodes().size(),
                "activeServices", ledger.getServices().stream()
                        .filter(ServiceRecord::active).count(),
                "activeTunnels", tunnelManager.getActiveTunnels().size()
        );
    }

    @GET @Path("/identity")
    public Map<String, String> getIdentity() {
        return Map.of(
                "nodeId", identity.getNodeId(),
                "publicKey", identity.getPublicKeyBase64()
        );
    }

    // =========================================================================
    // Node Registration
    // =========================================================================

    /** Register this node in the mesh ledger */
    @POST @Path("/node/register")
    public Response registerNode(RegisterRequest req) {
        try {
        NodeRegister entry = new NodeRegister(
                identity.getNodeId(),
                identity.getPublicKeyBase64(), // WireGuard key derived from same curve
                req.endpoints() != null ? req.endpoints() : List.of(),
                req.capabilities() != null ? req.capabilities() : List.of("tunnel"),
                req.displayName(),
                Instant.now(),
                identity.sign((identity.getNodeId() + "register").getBytes())
        );
        raft.submitEntry(entry);
        return Response.accepted(Map.of("status", "submitted", "nodeId", identity.shortId())).build();

        } catch (LicenseLimitException e) {
            return Response.status(Response.Status.PAYMENT_REQUIRED)
                    .entity(Map.of("error", e.getMessage()))
                    .build();
        }
    }

    /** Deregister this node from the mesh */
    @POST @Path("/node/deregister")
    public Response deregisterNode() {
        NodeDeregister entry = new NodeDeregister(
                identity.getNodeId(), "voluntary",
                Instant.now(),
                identity.sign((identity.getNodeId() + "deregister").getBytes())
        );
        raft.submitEntry(entry);
        return Response.accepted(Map.of("status", "submitted")).build();
    }

    // =========================================================================
    // Service Management
    // =========================================================================

    /** Expose a local service to specific peers */
    @POST @Path("/services/expose")
    public Response exposeService(ExposeRequest req) {
        ServiceRecord svc = registry.exposeService(
                req.serviceId(), req.protocol(), req.localBind(), req.allowedNodes());
        return Response.accepted(Map.of(
                "status", "submitted",
                "serviceId", svc.serviceId(),
                "assignedPort", svc.assignedPort(),
                "accessibleBy", svc.allowedNodes().size() + " nodes"
        )).build();
    }

    /** Revoke a service */
    @POST @Path("/services/{serviceId}/revoke")
    public Response revokeService(@PathParam("serviceId") String serviceId,
                                   RevokeRequest req) {
        registry.revokeService(serviceId, req.reason());
        tunnelManager.destroyTunnel(serviceId);
        return Response.accepted(Map.of("status", "submitted")).build();
    }

    /** List all services in the mesh */
    @GET @Path("/services")
    public Collection<ServiceRecord> listServices() {
        return ledger.getServices();
    }

    /** List services accessible by this node */
    @GET @Path("/services/accessible")
    public List<ServiceRecord> accessibleServices() {
        return registry.getAccessibleServices();
    }

    /** List services exposed by this node */
    @GET @Path("/services/exposed")
    public List<ServiceRecord> exposedServices() {
        return registry.getExposedServices();
    }

    // =========================================================================
    // Tunnel Management
    // =========================================================================

    /** Connect to a remote service (creates tunnel + intercept proxy) */
    @POST @Path("/connect/{serviceId}")
    public Response connectToService(@PathParam("serviceId") String serviceId) {
        if (accessMode.nativeDual()) {
            return Response.status(409).entity(Map.of("mode", "NATIVE_DUAL",
                    "error", "Use the provisioned endpoint namespace; this API creates STANDARD tunnels only")).build();
        }
        try {
            ActiveTunnel tunnel = tunnelManager.ensureTunnel(serviceId);
            // interceptProxy.startIntercept() is now called inside ensureTunnel()
            return Response.ok(Map.of(
                    "status",        tunnel.state().name(),
                    "serviceId",     serviceId,
                    "connectTo",     "127.0.0.1:" + tunnel.interceptLocalPort(),
                    "tunnelIf",      tunnel.ifName != null ? tunnel.ifName : "",
                    "peerTunnelIp",  tunnel.peerTunnelIp() != null ? tunnel.peerTunnelIp() : ""
            )).build();
        } catch (Exception e) {
            log.error("Connect failed for '{}'", serviceId, e);
            return Response.serverError()
                    .entity(Map.of("error", e.getMessage())).build();
        }
    }

    /** Disconnect from a service (destroys tunnel + stops proxy) */
    @POST @Path("/disconnect/{serviceId}")
    public Response disconnectService(@PathParam("serviceId") String serviceId) {
        interceptProxy.stopIntercept(serviceId);
        tunnelManager.destroyTunnel(serviceId);
        return Response.ok(Map.of("status", "disconnected", "serviceId", serviceId)).build();
    }

    /** List active tunnels */
    @GET @Path("/tunnels")
    public Map<String, ActiveTunnel> listTunnels() {
        return tunnelManager.getActiveTunnels();
    }

    // =========================================================================
    // Ledger & Mesh Queries
    // =========================================================================

    public record NodeWithStatus(
            String nodeId, String wireguardPubkey, java.util.List<String> endpoints,
            java.util.List<String> capabilities, String displayName,
            java.time.Instant registeredAt, boolean active, boolean online, boolean registered
    ) {}

    /** List all registered nodes */
    @GET @Path("/nodes")
    public java.util.List<NodeWithStatus> listNodes() {
        // Ledger-registered nodes
        java.util.Map<String, LedgerStore.NodeRecord> ledgerNodes = ledger.getNodes().stream()
                .filter(n -> n.active())
                .collect(java.util.stream.Collectors.toMap(n -> n.nodeId(), n -> n));

        // Gossip-discovered peers (may include unregistered nodes)
        java.util.Set<String> onlinePeers = gossip.getKnownPeers().stream()
                .map(p -> p.nodeId())
                .collect(java.util.stream.Collectors.toSet());

        // Always include self
        onlinePeers.add(identity.getNodeId());

        java.util.List<NodeWithStatus> result = new java.util.ArrayList<>();

        // Add all ledger-registered nodes with online status
        ledgerNodes.values().stream()
                .filter(n -> n.active())
                .forEach(n -> result.add(new NodeWithStatus(
                        n.nodeId(), n.wireguardPubkey(), n.endpoints(),
                        n.capabilities(), n.displayName(), n.registeredAt(),
                        n.active(), onlinePeers.contains(n.nodeId()), true
                )));

        // Add gossip-discovered peers not yet in ledger
        gossip.getKnownPeers().stream()
                .filter(p -> !ledgerNodes.containsKey(p.nodeId()))
                .forEach(p -> result.add(new NodeWithStatus(
                        p.nodeId(), p.pubkey(),
                        java.util.List.of(p.address().getHostAddress() + ":" + p.port()),
                        java.util.List.of(), "Unknown",
                        java.time.Instant.ofEpochMilli(p.lastSeen()),
                        true, true, false  // active=true, online=true, registered=false
                )));

        // Add self if not already in ledger
        if (!ledgerNodes.containsKey(identity.getNodeId())) {
            result.add(new NodeWithStatus(
                    identity.getNodeId(), identity.getPublicKeyBase64(),
                    java.util.List.of(), java.util.List.of(), "This node",
                    java.time.Instant.now(), true, true, false
            ));
        }

        return result;
    }

    /** List known peers (gossip layer, may include unregistered) */
    @GET @Path("/peers")
    public Collection<GossipService.PeerInfo> listPeers() {
        return gossip.getKnownPeers();
    }

    /** Get ledger block by index */
    @GET @Path("/ledger/block/{index}")
    public Response getBlock(@PathParam("index") long index) {
        return ledger.getBlock(index)
                .map(b -> Response.ok(b).build())
                .orElse(Response.status(404).build());
    }

    /** Get chain info */
    @GET @Path("/ledger/info")
    public Map<String, Object> ledgerInfo() {
        return Map.of(
                "height", ledger.getChainHeight(),
                "lastBlockHash", ledger.getLastBlock() != null
                        ? ledger.getLastBlock().hash().substring(0, 32) : "genesis"
        );
    }

// =========================================================================
// Delete / Remove actions
// =========================================================================

    /** Force-deregister any node by ID (admin action) */
    @DELETE @Path("/nodes/{nodeId}")
    public Response removeNode(@PathParam("nodeId") String nodeId) {
        LedgerEntry.NodeDeregister entry = new LedgerEntry.NodeDeregister(
                nodeId, "admin-removed",
                java.time.Instant.now(),
                identity.sign((nodeId + "deregister").getBytes())
        );
        raft.submitEntry(entry);
        return Response.ok(Map.of("status", "submitted", "nodeId", nodeId)).build();
    }

    /** Delete/revoke a tunnel (connector side) */
    @DELETE @Path("/tunnels/{serviceId}")
    public Response deleteTunnel(@PathParam("serviceId") String serviceId) {
        interceptProxy.stopIntercept(serviceId);
        tunnelManager.destroyTunnel(serviceId);
        return Response.ok(Map.of("status", "disconnected", "serviceId", serviceId)).build();
    }

    // =========================================================================
    // Request DTOs
    // =========================================================================

    public record RegisterRequest(List<String> endpoints, List<String> capabilities,
                                   String displayName) {}
    public record ExposeRequest(String serviceId, String protocol, String localBind,
                                 List<String> allowedNodes) {}
    public record RevokeRequest(String reason) {}


}
