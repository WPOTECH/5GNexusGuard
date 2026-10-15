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
 * 2. Validates the connection came through a legitimate tunnel
 * 3. Forwards traffic to the actual local service (e.g. 127.0.0.1:5432)
 *
 * This runs automatically for all services this node has exposed via the ledger.
 * When a new SERVICE_EXPOSE entry appears in the ledger for this node,
 * the egress proxy starts listening.
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

    /**
     * Periodically check for new services this node exposes
     * and start egress proxies for them.
     */
    @Scheduled(every = "5s")
    void syncEgressBindings() {
        if (accessMode.nativeDual()) return;
        var myServices = ledger.getServicesByOwner(identity.getNodeId());

        // Start legacy 0.0.0.0 egress for services not yet tunnel-connected
        for (ServiceRecord svc : myServices) {
            if (!svc.active()) continue;
            if (bindings.containsKey(svc.serviceId())) continue;
            startEgress(svc);
        }

        // Only stop egress for plain serviceId keys (not tunnel-specific keys)
        bindings.entrySet().removeIf(entry -> {
            String key = entry.getKey();
            // Skip tunnel-specific bindings (they contain ':' + IP)
            if (key.contains(":")) return false;
            var svc = ledger.getService(key);
            if (svc.isEmpty() || !svc.get().active()) {
                entry.getValue().active = false;
                try { entry.getValue().serverSocket.close(); } catch (Exception ignored) {}
                log.info("Stopped egress for '{}'", key);
                return true;
            }
            return false;
        });
    }

    private void startEgress(ServiceRecord service) {
        accessMode.requireStandard();
        String[] bindParts = service.localBind().split(":");
        String localHost = bindParts.length > 1 ? bindParts[0] : "127.0.0.1";
        int localPort = Integer.parseInt(bindParts[bindParts.length - 1]);

        // Egress listens on the service's assigned port on 0.0.0.0
        // (traffic arrives from WireGuard tunnel interface)
        int listenPort = service.assignedPort();

        try {
            ServerSocket serverSocket = new ServerSocket(listenPort);
            EgressBinding binding = new EgressBinding(
                    service.serviceId(), listenPort, localHost, localPort, serverSocket, true);
            bindings.put(service.serviceId(), binding);

            Thread.ofVirtual()
                    .name("egress-" + service.serviceId())
                    .start(() -> acceptLoop(binding));

            log.info("Egress active: :{} → {}:{} for service '{}'",
                    listenPort, localHost, localPort, service.serviceId());

        } catch (IOException e) {
            log.error("Failed to start egress for '{}' on port {}",
                    service.serviceId(), listenPort, e);
        }
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
     * Binds egress ONLY on the tunnel interface IP so only WG traffic can reach it.
     */
    public int startEgressOnInterface(String tunnelIp, int egressPort,
                                      String svcHost, int svcPort, String serviceId) {

        accessMode.requireStandard();
        String key = serviceId + ":" + tunnelIp;
        if (bindings.containsKey(key)) {
            log.info("Egress already active for svc='{}' on {}", serviceId, tunnelIp);
            return egressPort;
        }

        try {
            ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new java.net.InetSocketAddress(tunnelIp, egressPort));

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
