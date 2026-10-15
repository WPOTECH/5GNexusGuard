package com.defenderlink.mesh.tunnel.nativeaccess;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/** Restart-only switch; never fall back to STANDARD on a spelling error. */
@ApplicationScoped
public class AccessMode {
    @ConfigProperty(name = "mesh.access.mode", defaultValue = "STANDARD")
    String mode;

    @ConfigProperty(name = "mesh.native.gateway-mode", defaultValue = "NATIVE")
    String gateway = "NATIVE";

    void validate(@Observes StartupEvent event) { if (nativeDual()) gatewayMode(); }

    public String gatewayMode() {
        if (!"NATIVE".equals(gateway) && !"EXTERNAL_CONFIG".equals(gateway))
            throw new IllegalStateException("mesh.native.gateway-mode must be NATIVE or EXTERNAL_CONFIG");
        return gateway;
    }

    public boolean exportsLease() {
        return nativeDual() && "NATIVE".equals(gatewayMode());
    }

    public boolean nativeDual() {
        if ("STANDARD".equals(mode)) return false;
        if ("NATIVE_DUAL".equals(mode)) return true;
        throw new IllegalStateException("mesh.access.mode must be STANDARD or NATIVE_DUAL");
    }

    public void requireStandard() {
        if (nativeDual()) throw new IllegalStateException(
                "NATIVE_DUAL requires separately provisioned IKEv2/ESP + WireGuard; STANDARD negotiation is disabled");
    }
}
