package com.defenderlink.mesh.tunnel;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class TunnelManagerLifecycleTest {
    static class Fake extends TunnelManager {
        final List<List<String>> calls = new ArrayList<>();
        String name = "dl-c-test";
        String alias;
        int index=11;
        boolean exists=true, failAdd=false, failDelete=false;
        Fake() { alias=interfaceOwner; ownedInterfaces.put(name,index); }
        @Override void exec(String... command) {
            calls.add(List.of(command));
            if (List.of(command).contains("add") && failAdd) throw new IllegalStateException("EEXIST");
            if (List.of(command).contains("delete")) {
                if (failDelete) throw new IllegalStateException("injected deletion failure");
                exists=false;
            }
        }
        @Override String execCapture(String... command) {
            return exists ? "[{\"ifname\":\""+name+"\",\"ifindex\":"+index+",\"ifalias\":\""+alias+"\"}]" : "[]";
        }
    }
    @Test void fullServiceAndPeerScopeAvoidsOldTruncationCollisions() {
        Set<String> names=new HashSet<>();
        for (String service:List.of("prototype-a","prototype-b"))
            for (String peer:List.of("peer-a","peer-b"))
                for (String role:List.of("c","o")) {
                    String name=TunnelManager.interfaceName("dl",role,service,"local",peer);
                    assertTrue(name.length()<=15);assertTrue(names.add(name));
                }
        assertThrows(IllegalArgumentException.class,()->TunnelManager.interfaceName("long-prefix","c","s","l","p"));
    }
    @Test void existingNameIsNeverDeletedOnCreationFailure() {
        Fake f=new Fake();f.failAdd=true;
        assertThrows(IllegalStateException.class,()->f.createOwnedInterface(f.name));
        assertEquals(1,f.calls.size());assertFalse(f.calls.getFirst().contains("delete"));
    }
    @Test void renamedReplacementIsNotDeletedAndFailedClaimRemains() {
        Fake f=new Fake();f.index=12;
        assertThrows(IllegalStateException.class,()->f.deleteOwnedInterface(f.name));
        assertTrue(f.calls.isEmpty());assertTrue(f.ownedInterfaces.containsKey(f.name));
        f.index=11;f.alias="foreign";
        assertThrows(IllegalStateException.class,()->f.deleteOwnedInterface(f.name));
        assertTrue(f.calls.isEmpty());
    }
    @Test void failedTeardownStaysVisibleUntilSuccessfulRetry() throws Exception {
        Fake f=new Fake();
        var field=TunnelManager.class.getDeclaredField("tunnels");field.setAccessible(true);
        @SuppressWarnings("unchecked") Map<String,TunnelManager.ActiveTunnel> tunnels=(Map<String,TunnelManager.ActiveTunnel>)field.get(f);
        var at=new TunnelManager.ActiveTunnel("svc",f.name,"10.200.1.1/30","public",51820,"peer",TunnelManager.TunnelRole.CONNECTOR,15100);
        tunnels.put("conn:svc",at);f.failDelete=true;f.destroyTunnel("svc");
        assertEquals(TunnelManager.TunnelState.FAILED,at.state());assertTrue(tunnels.containsKey("conn:svc"));
        assertNotNull(at.error());assertTrue(f.ownedInterfaces.containsKey(f.name));
        f.failDelete=false;f.destroyTunnel("svc");assertTrue(tunnels.isEmpty());assertTrue(f.ownedInterfaces.isEmpty());
    }
}
