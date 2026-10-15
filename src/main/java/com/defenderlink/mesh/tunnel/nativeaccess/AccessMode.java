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

    void validate(@Observes StartupEvent event) { nativeDual(); }

    public boolean nativeDual() {
        if ("STANDARD".equals(mode)) return false;
        if ("NATIVE_DUAL".equals(mode)) return true;
        throw new IllegalStateException("mesh.access.mode must be STANDARD or NATIVE_DUAL");
    }

    public void requireStandard() {
        if (nativeDual()) throw new IllegalStateException(
                "NATIVE_DUAL uses the provisioned endpoint namespace; STANDARD negotiation is disabled");
    }
}
