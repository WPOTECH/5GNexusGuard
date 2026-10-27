package com.defenderlink.mesh.tunnel;


import com.defenderlink.mesh.identity.NodeIdentity;
import com.defenderlink.mesh.ledger.store.LedgerStore;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;

@Path("/internal/tunnel")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class TunnelNegotiationResource {

    private static final Logger log = LoggerFactory.getLogger(TunnelNegotiationResource.class);

    @Inject TunnelManager tunnelManager;
    @Inject NodeIdentity identity;
    @Inject LedgerStore ledger;

    @ConfigProperty(name = "mesh.node.public-endpoint", defaultValue = "127.0.0.1:51820")
    String publicEndpoint;

    @ConfigProperty(name = "mesh.tunnel.listen-port-start", defaultValue = "51820")
    int listenPortStart = 51820;

    public record NegotiateRequest(
            String serviceId,
            String initiatorNodeId,
            String initiatorWgPubkey,
            String initiatorTunnelIp,
            String initiatorEndpoint,
            String signature
    ) {}

    public record NegotiateResponse(
            String ownerWgPubkey,
            String ownerTunnelIp,
            String ownerEndpoint,
            int listenPort,
            int egressPort
    ) {}

    @POST
    @Path("/negotiate")
    public Response negotiate(NegotiateRequest req) {
        log.info("Negotiate request: svc='{}' from='{}'", req.serviceId(), req.initiatorNodeId());

        // 1. Verify initiator is a known ledger node
        LedgerStore.NodeRecord initiator = ledger.getNode(req.initiatorNodeId()).orElse(null);
        if (initiator == null) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("{\"error\":\"unknown initiator\"}").build();
        }

        // 2. Verify Ed25519 signature using the node's identity key (nodeId is hex Ed25519 pubkey)
        String signable = req.serviceId() + req.initiatorNodeId() + req.initiatorWgPubkey();
        log.info("DEBUG verify: signable='{}' nodeId='{}' wgPubkey='{}'",
                signable, req.initiatorNodeId(), req.initiatorWgPubkey());
        byte[] identityPubKey = hexToBytes(initiator.nodeId());
        if (!NodeIdentity.verify(
                signable.getBytes(),
                java.util.Base64.getDecoder().decode(req.signature()),
                hexToBytes(initiator.nodeId()))) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("{\"error\":\"invalid signature\"}").build();
        }

        // 3. Verify this node owns the service
        LedgerStore.ServiceRecord svc = ledger.getService(req.serviceId()).orElse(null);
        if (svc == null || !svc.ownerNodeId().equals(identity.getNodeId())) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"service not owned by this node\"}").build();
        }

        // 4. Verify initiator is in the allowed list
        if (!svc.allowedNodes().contains(req.initiatorNodeId())) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("{\"error\":\"access denied\"}").build();
        }

        try {
            TunnelManager.ReciprocatedTunnel rt = tunnelManager.createOwnerSideTunnel(
                    req.serviceId(),
                    req.initiatorNodeId(),
                    req.initiatorWgPubkey(),
                    req.initiatorTunnelIp(),
                    req.initiatorEndpoint()
            );

            return Response.ok(new NegotiateResponse(
                    rt.wgPubkey(),
                    rt.tunnelIp(),
                    TunnelManager.advertisedEndpoint(publicEndpoint, listenPortStart, rt.listenPort()),
                    rt.listenPort(),
                    rt.egressPort()
            )).build();

        } catch (Exception e) {
            log.error("createOwnerSideTunnel failed for svc='{}'", req.serviceId(), e);
            return Response.serverError()
                    .entity("{\"error\":\"" + e.getMessage() + "\"}").build();
        }
    }

    @DELETE
    @Path("/negotiate/{serviceId}/{initiatorNodeId}")
    public Response teardown(
            @PathParam("serviceId") String serviceId,
            @PathParam("initiatorNodeId") String initiatorNodeId) {
        log.info("Teardown: svc='{}' from='{}'", serviceId, initiatorNodeId);
        tunnelManager.destroyOwnerSideTunnel(serviceId, initiatorNodeId);
        return Response.noContent().build();
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }
}
