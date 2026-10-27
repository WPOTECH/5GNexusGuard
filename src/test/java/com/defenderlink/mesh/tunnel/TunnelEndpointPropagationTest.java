package com.defenderlink.mesh.tunnel;

import com.defenderlink.mesh.identity.NodeIdentity;
import com.defenderlink.mesh.ledger.store.LedgerStore;
import org.junit.jupiter.api.Test;
import java.security.*;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class TunnelEndpointPropagationTest {
    @Test void allocatedPortsKeepTheAdvertisedHostAndIpv6Brackets() {
        assertEquals("192.0.2.1:51820",TunnelManager.advertisedEndpoint("192.0.2.1:51820",51820,51820));
        assertEquals("192.0.2.1:51821",TunnelManager.advertisedEndpoint("192.0.2.1:51820",51820,51821));
        assertEquals("gateway.example:51822",TunnelManager.advertisedEndpoint("gateway.example:51820",51820,51822));
        assertEquals("[2001:db8::1]:51821",TunnelManager.advertisedEndpoint("[2001:db8::1]:51820",51820,51821));
    }
    @Test void explicitPublicPortMappingIsPreservedAndBounded() {
        assertEquals("gateway.example:60000",TunnelManager.advertisedEndpoint("gateway.example:60000",51820,51820));
        assertEquals("gateway.example:60001",TunnelManager.advertisedEndpoint("gateway.example:60000",51820,51821));
        assertEquals("gateway.example:60001",TunnelManager.validatedEndpoint("gateway.example:60001"));
        assertThrows(IllegalArgumentException.class,()->TunnelManager.advertisedEndpoint("gateway.example:65535",51820,51821));
        assertThrows(IllegalArgumentException.class,()->TunnelManager.advertisedEndpoint("gateway.example:60000",0,51820));
        assertThrows(IllegalArgumentException.class,()->TunnelManager.advertisedEndpoint("gateway.example:60000",51821,51820));
    }
    @Test void malformedEndpointsAndInvalidAllocatedPortsDoNotGuessAFallback() {
        for (String invalid:List.of("192.0.2.1","192.0.2.1:0","192.0.2.1:65536","user@192.0.2.1:51820",
                "192.0.2.1:51820/path","192.0.2.1:51820?port=1","192.0.2.1:51820#fragment"))
            assertThrows(IllegalArgumentException.class,()->TunnelManager.advertisedEndpoint(invalid,51820,51821),invalid);
        for (int invalid:List.of(-1,0,65536))
            assertThrows(IllegalArgumentException.class,()->TunnelManager.advertisedEndpoint("192.0.2.1:51820",51820,invalid));
    }

    @Test void ownerResponseAdvertisesTheAllocatedSecondServicePort() throws Exception {
        KeyPair client=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] publicDer=client.getPublic().getEncoded();
        String clientId=HexFormat.of().formatHex(Arrays.copyOfRange(publicDer,publicDer.length-32,publicDer.length));
        String ownerId="b".repeat(64);
        String wgKey=Base64.getEncoder().encodeToString(new byte[32]);
        var node=new LedgerStore.NodeRecord(clientId,wgKey,List.of("192.0.2.1:8443"),List.of("tunnel"),"client",Instant.now(),true);
        var service=new LedgerStore.ServiceRecord("prototype-b",ownerId,"tcp","127.0.0.1:18080",15101,List.of(clientId),null,Instant.now(),true);
        var resource=new TunnelNegotiationResource();
        resource.publicEndpoint="192.0.2.2:51820";
        resource.identity=new NodeIdentity() { @Override public String getNodeId(){return ownerId;} };
        resource.ledger=new LedgerStore() {
            @Override public Optional<NodeRecord> getNode(String id){return Optional.of(node);}
            @Override public Optional<ServiceRecord> getService(String id){return Optional.of(service);}
        };
        resource.tunnelManager=new TunnelManager() {
            @Override public ReciprocatedTunnel createOwnerSideTunnel(String svc,String id,String key,String ip,String endpoint) {
                return new ReciprocatedTunnel("dl-o-unit",wgKey,"10.200.2.2/30",51821,15101);
            }
        };
        Signature signer=Signature.getInstance("Ed25519");signer.initSign(client.getPrivate());
        signer.update(("prototype-b"+clientId+wgKey).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        var request=new TunnelNegotiationResource.NegotiateRequest("prototype-b",clientId,wgKey,"10.200.2.1/30","192.0.2.1:51821",Base64.getEncoder().encodeToString(signer.sign()));
        try (var response=resource.negotiate(request)) {
            assertEquals(200,response.getStatus());
            var negotiated=(TunnelNegotiationResource.NegotiateResponse)response.getEntity();
            assertEquals(51821,negotiated.listenPort());
            assertEquals("192.0.2.2:51821",negotiated.ownerEndpoint());
        }
    }
}
