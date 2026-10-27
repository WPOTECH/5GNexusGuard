package com.defenderlink.mesh.proxy;

import com.defenderlink.mesh.identity.NodeIdentity;
import com.defenderlink.mesh.ledger.store.LedgerStore;
import com.defenderlink.mesh.ledger.store.LedgerStore.ServiceRecord;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Egress proxy — the service-side counterpart to InterceptProxy.
 *
 * For each service THIS node exposes:
 * 1. Listens on the WireGuard tunnel interface for incoming connections
 * 2. Uses the explicit listener established by tunnel negotiation
 * 3. Forwards traffic to the actual local service (e.g. 127.0.0.1:5432)
 *
 * Listeners open only after explicit tunnel negotiation. Ledger publication
 * alone does not authorize opening a plaintext underlay listener.
 */
@ApplicationScoped
public class EgressProxy {

    private static final Logger log = LoggerFactory.getLogger(EgressProxy.class);
    private static final int BUFFER_SIZE = 8192;

    @Inject
    com.defenderlink.mesh.tunnel.nativeaccess.AccessMode accessMode;

    @Inject
    NodeIdentity identity;

    @Inject
    LedgerStore ledger;

    private final Map<String, EgressBinding> bindings = new ConcurrentHashMap<>();

    /** Ledger publication must never create an unauthenticated plaintext listener. */
    @Scheduled(every = "5s")
    void syncEgressBindings() {
        if (accessMode.nativeDual()) return;
        // Withdraw only obsolete listeners owned by this proxy instance. Keep
        // negotiated address-bound listeners; opening them requires TunnelManager.
        bindings.entrySet().removeIf(entry -> {
            EgressBinding binding = entry.getValue();
            var address = binding.serverSocket.getInetAddress();
            if (address != null && !address.isAnyLocalAddress()) return false;
            binding.active = false;
            try {
                binding.serverSocket.close();
                log.info("Closed obsolete wildcard egress for '{}'", binding.serviceId);
                return true;
            } catch (IOException failed) {
                log.warn("Wildcard egress close failed for '{}'; retaining cleanup tracking", binding.serviceId);
                return false;
            }
        });
    }

    private void stopEgress(String serviceId) {
        EgressBinding binding = bindings.remove(serviceId);
        if (binding != null) {
            binding.active = false;
            try { binding.serverSocket.close(); } catch (IOException ignored) {}
            log.info("Stopped egress for '{}'", serviceId);
        }
    }

    private void acceptLoop(EgressBinding binding) {
        while (binding.active) {
            try {
                Socket inbound = binding.serverSocket.accept();
                if (!binding.active) { inbound.close(); break; }
                Thread.ofVirtual()
                        .name("egress-conn-" + binding.serviceId)
                        .start(() -> forwardToLocal(inbound, binding));
            } catch (IOException e) {
                if (binding.active) log.debug("Egress accept error: {}", e.getMessage());
            }
        }
    }

    // Add this overload — existing acceptLoop(EgressBinding) can stay untouched
    private void acceptLoop(EgressBinding b, String bindingKey) {
        while (b.active) {
            try {
                Socket inbound = b.serverSocket.accept();
                if (!b.active) { inbound.close(); break; }
                Thread.ofVirtual()
                        .name("egress-conn-" + b.serviceId)
                        .start(() -> forwardToLocal(inbound, b));
            } catch (java.io.IOException e) {
                if (b.active) log.warn("Egress accept error [{}]: {}", bindingKey, e.getMessage());
            }
        }
    }

    private void forwardToLocal(Socket inbound, EgressBinding binding) {
        try (Socket localSocket = new Socket(binding.localHost, binding.localPort)) {
            Thread up = Thread.ofVirtual().start(() ->
                    pipe(inbound, localSocket));
            Thread down = Thread.ofVirtual().start(() ->
                    pipe(localSocket, inbound));
            up.join();
            down.join();
        } catch (Exception e) {
            log.debug("Egress forward failed for '{}': {}", binding.serviceId, e.getMessage());
        } finally {
            try { inbound.close(); } catch (IOException ignored) {}
        }
    }

    private void pipe(Socket from, Socket to) {
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            byte[] buf = new byte[BUFFER_SIZE];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException ignored) {
        } finally {
            try { from.shutdownInput(); } catch (IOException ignored) {}
            try { to.shutdownOutput(); } catch (IOException ignored) {}
        }
    }

    public Map<String, EgressBinding> getBindings() {
        return Map.copyOf(bindings);
    }

    public static class EgressBinding {
        public final String serviceId;
        public final int listenPort;
        public final String localHost;
        public final int localPort;
        public final ServerSocket serverSocket;
        public volatile boolean active;

        public EgressBinding(String serviceId, int listenPort, String localHost,
                              int localPort, ServerSocket serverSocket, boolean active) {
            this.serviceId = serviceId;
            this.listenPort = listenPort;
            this.localHost = localHost;
            this.localPort = localPort;
            this.serverSocket = serverSocket;
            this.active = active;
        }
    }

    /**
     * Called from TunnelManager.createOwnerSideTunnel() after WG interface is up.
     * Binds to the negotiated tunnel address. Ingress-device enforcement is a
     * separate kernel routing/firewall property, not implied by an IP bind.
     */
    public int startEgressOnInterface(String tunnelIp, int egressPort,
                                      String svcHost, int svcPort, String serviceId) {

        accessMode.requireStandard();
        if (tunnelIp == null || tunnelIp.isBlank())
            throw new IllegalArgumentException("Explicit negotiated tunnel address required");
        final java.net.InetAddress address;
        try { address = java.net.InetAddress.getByName(tunnelIp); }
        catch (java.net.UnknownHostException invalid) {
            throw new IllegalArgumentException("Invalid negotiated tunnel address");
        }
        if (address.isAnyLocalAddress())
            throw new IllegalArgumentException("Wildcard egress binding is forbidden");
        String key = serviceId + ":" + tunnelIp;
        if (bindings.containsKey(key)) {
            log.info("Egress already active for svc='{}' on {}", serviceId, tunnelIp);
            return egressPort;
        }

        try {
            ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new java.net.InetSocketAddress(address, egressPort));

            EgressBinding b = new EgressBinding(serviceId, egressPort, svcHost, svcPort, ss, true);
            bindings.put(key, b);

            Thread.ofVirtual().name("egress-" + serviceId + "-" + tunnelIp)
                    .start(() -> acceptLoop(b, key));

            log.info("Egress bound: {}:{} → {}:{} for svc='{}'",
                    tunnelIp, egressPort, svcHost, svcPort, serviceId);
            return egressPort;

        } catch (java.io.IOException e) {
            throw new RuntimeException(
                    "Egress bind failed on " + tunnelIp + ":" + egressPort, e);
        }
    }

    /**
     * Stop a tunnel-specific egress binding. Called from destroyOwnerSideTunnel().
     */
    public void stopEgressOnInterface(String serviceId, String tunnelIp) {
        String key = serviceId + ":" + tunnelIp;
        EgressBinding b = bindings.remove(key);
        if (b == null) return;
        b.active = false;
        try { b.serverSocket.close(); } catch (java.io.IOException ignored) {}
        log.info("Stopped egress for svc='{}' on {}", serviceId, tunnelIp);
    }
}
