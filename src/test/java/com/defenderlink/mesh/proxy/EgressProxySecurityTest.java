package com.defenderlink.mesh.proxy;

import com.defenderlink.mesh.identity.NodeIdentity;
import com.defenderlink.mesh.ledger.store.LedgerStore;
import com.defenderlink.mesh.tunnel.nativeaccess.AccessMode;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.net.*;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class EgressProxySecurityTest {
    static class UnboundFixtureSocket extends ServerSocket {
        final InetAddress address;
        boolean closed, failClose;
        UnboundFixtureSocket(String address) throws IOException { this.address=InetAddress.getByName(address); }
        @Override public InetAddress getInetAddress() { return address; }
        @Override public void close() throws IOException {
            if (failClose) throw new IOException("injected close failure");
            closed=true;super.close();
        }
    }
    static LedgerStore.ServiceRecord deniedService() {
        String owner="b".repeat(64);
        return new LedgerStore.ServiceRecord("denied",owner,"tcp","127.0.0.1:0",0,List.of(owner),null,Instant.now(),true);
    }
    static EgressProxy proxy(boolean nativeMode) {
        var p=new EgressProxy();
        p.accessMode=new AccessMode() {
            @Override public boolean nativeDual(){return nativeMode;}
            @Override public void requireStandard(){if(nativeMode)throw new IllegalStateException("native mode");}
        };
        p.identity=new NodeIdentity() { @Override public String getNodeId(){return "b".repeat(64);} };
        p.ledger=new LedgerStore() {
            @Override public List<ServiceRecord> getServicesByOwner(String id){return List.of(deniedService());}
            @Override public Optional<ServiceRecord> getService(String id){return Optional.of(deniedService());}
        };
        return p;
    }
    @SuppressWarnings("unchecked")
    static Map<String,EgressProxy.EgressBinding> bindings(EgressProxy p) throws Exception {
        var f=EgressProxy.class.getDeclaredField("bindings");f.setAccessible(true);
        return (Map<String,EgressProxy.EgressBinding>)f.get(p);
    }
    @Test void existingWildcardIsWithdrawnEvenForActiveDeniedService() throws Exception {
        EgressProxy p=proxy(false);
        try (var socket=new UnboundFixtureSocket("0.0.0.0")) {
            var b=new EgressProxy.EgressBinding("denied",0,"127.0.0.1",0,socket,true);
            bindings(p).put("denied",b); // Suppresses old constructor; never opens a wildcard host listener.
            p.syncEgressBindings();
            assertFalse(b.active);assertTrue(socket.closed);assertTrue(p.getBindings().isEmpty());
        }
    }
    @Test void publishedDeniedServiceNeverCreatesAPortListener() throws Exception {
        EgressProxy p=proxy(false);
        try {
            p.syncEgressBindings();
            assertTrue(p.getBindings().isEmpty());
        } finally {
            for (var b:p.getBindings().values()) { b.active=false;b.serverSocket.close(); }
        }
    }
    @Test void negotiatedAddressBindingSurvivesReconciliationAndClosesOnTeardown() {
        EgressProxy p=proxy(false);
        try {
            p.startEgressOnInterface("127.0.0.1",0,"127.0.0.1",0,"allowed");
            var b=p.getBindings().get("allowed:127.0.0.1");
            assertNotNull(b);assertTrue(b.serverSocket.getInetAddress().isLoopbackAddress());
            assertFalse(b.serverSocket.getInetAddress().isAnyLocalAddress());
            p.syncEgressBindings();assertSame(b,p.getBindings().get("allowed:127.0.0.1"));
            p.stopEgressOnInterface("allowed","127.0.0.1");
            assertFalse(b.active);assertTrue(b.serverSocket.isClosed());assertTrue(p.getBindings().isEmpty());
        } finally { p.stopEgressOnInterface("allowed","127.0.0.1"); }
    }
    @Test void explicitAnyLocalArgumentsNeverOpenAnEgressListener() {
        EgressProxy p=proxy(false);
        for (String any:List.of("0.0.0.0","::","[::]"))
            assertThrows(IllegalArgumentException.class,()->p.startEgressOnInterface(any,0,"127.0.0.1",0,"denied"));
        assertTrue(p.getBindings().isEmpty());
    }
    @Test void failedWildcardWithdrawalKeepsTrackingForRetry() throws Exception {
        EgressProxy p=proxy(false);
        try (var socket=new UnboundFixtureSocket("0.0.0.0")) {
            var b=new EgressProxy.EgressBinding("denied",0,"127.0.0.1",0,socket,true);
            bindings(p).put("denied",b);socket.failClose=true;p.syncEgressBindings();
            assertFalse(b.active);assertFalse(socket.closed);assertSame(b,p.getBindings().get("denied"));
            socket.failClose=false;p.syncEgressBindings();assertTrue(socket.closed);assertTrue(p.getBindings().isEmpty());
        }
    }
    @Test void nativeModeDoesNotEnterTheStandardEgressPath() {
        EgressProxy p=proxy(true);p.syncEgressBindings();
        assertThrows(IllegalStateException.class,()->p.startEgressOnInterface("127.0.0.1",0,"127.0.0.1",0,"native"));
        assertTrue(p.getBindings().isEmpty());
    }
}
