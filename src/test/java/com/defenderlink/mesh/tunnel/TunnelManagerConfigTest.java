package com.defenderlink.mesh.tunnel;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class TunnelManagerConfigTest {
    @TempDir Path temporary;

    @Test
    void confinedConfigDirectoryOverrideLeavesProductDataDirectoryUnchanged() throws Exception {
        TunnelManager manager = new TunnelManager();
        manager.dataDir = temporary.resolve("ledger-data").toString();
        Path confined = temporary.resolve("wireguard");
        manager.configDirOverride = Optional.of(confined.toString());
        Method write = TunnelManager.class.getDeclaredMethod("writeConfig", String.class,
                String.class, int.class, String.class, String.class, String.class);
        write.setAccessible(true);
        Path config = Path.of((String) write.invoke(manager, "dl-test", "test-key", 51820,
                "peer", "192.0.2.1:51820", "10.79.0.1"));
        assertEquals(confined.resolve("dl-test.conf"), config);
        assertTrue(Files.exists(config));
        assertFalse(Files.exists(temporary.resolve("ledger-data/wg-configs")));

        manager.configDirOverride = Optional.empty();
        Path defaultConfig = Path.of((String) write.invoke(manager, "dl-default", "test-key", 51820,
                "peer", "192.0.2.1:51820", "10.79.0.1"));
        assertEquals(temporary.resolve("ledger-data/wg-configs/dl-default.conf"), defaultConfig);
        assertTrue(Files.exists(defaultConfig));
    }

    @Test
    void configReplacementNeverFollowsExistingSymlink() throws Exception {
        TunnelManager manager = new TunnelManager();
        manager.dataDir = temporary.resolve("ledger").toString();
        Path confined = temporary.resolve("private-wireguard");
        Files.createDirectory(confined);
        Files.setPosixFilePermissions(confined, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        manager.configDirOverride = Optional.of(confined.toString());
        Path outside = temporary.resolve("outside");
        Files.writeString(outside, "sentinel");
        Files.createSymbolicLink(confined.resolve("dl-test.conf"), outside);
        Method write = TunnelManager.class.getDeclaredMethod("writeConfig", String.class,
                String.class, int.class, String.class, String.class, String.class);
        write.setAccessible(true);
        write.invoke(manager, "dl-test", "test-key", 51820, "peer", "192.0.2.1:51820", "10.79.0.1");
        assertEquals("sentinel", Files.readString(outside));
        assertFalse(Files.isSymbolicLink(confined.resolve("dl-test.conf")));
        assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(confined.resolve("dl-test.conf")));
    }

    @Test
    void overrideDirectoryMustBePrivateAndNotSymlinked() throws Exception {
        TunnelManager manager = new TunnelManager();
        manager.dataDir = temporary.resolve("ledger").toString();
        Path shared = temporary.resolve("shared");
        Files.createDirectory(shared);
        Files.setPosixFilePermissions(shared, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        manager.configDirOverride = Optional.of(shared.toString());
        Method write = TunnelManager.class.getDeclaredMethod("writeConfig", String.class,
                String.class, int.class, String.class, String.class, String.class);
        write.setAccessible(true);
        assertThrows(java.lang.reflect.InvocationTargetException.class, () ->
                write.invoke(manager, "dl-test", "test-key", 51820, "peer", "192.0.2.1:51820", "10.79.0.1"));
        assertFalse(Files.exists(shared.resolve("dl-test.conf")));

        Path symlink = temporary.resolve("link");
        Files.createSymbolicLink(symlink, shared);
        manager.configDirOverride = Optional.of(symlink.toString());
        assertThrows(java.lang.reflect.InvocationTargetException.class, () ->
                write.invoke(manager, "dl-test", "test-key", 51820, "peer", "192.0.2.1:51820", "10.79.0.1"));
    }

    @Test
    void legacyDefaultDirectoryIsTightenedBeforePrivateConfigWrite() throws Exception {
        TunnelManager manager = new TunnelManager();
        Path data = Files.createDirectory(temporary.resolve("ledger-data"));
        Files.setPosixFilePermissions(data,
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        Path legacy = Files.createDirectory(data.resolve("wg-configs"));
        Files.setPosixFilePermissions(legacy,
                java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        manager.dataDir = data.toString();
        manager.configDirOverride = Optional.empty();
        Method write = TunnelManager.class.getDeclaredMethod("writeConfig", String.class,
                String.class, int.class, String.class, String.class, String.class);
        write.setAccessible(true);
        Path config = Path.of((String) write.invoke(manager, "dl-test", "test-key", 51820,
                "peer", "192.0.2.1:51820", "10.79.0.1"));
        assertEquals(legacy.resolve("dl-test.conf"), config);
        assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"),
                Files.getPosixFilePermissions(legacy));
        assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(config));
    }

    @Test
    void replaceableAncestorIsRejectedBeforeCreatingConfigDirectory() throws Exception {
        TunnelManager manager = new TunnelManager();
        manager.dataDir = temporary.resolve("ledger").toString();
        Path shared = temporary.resolve("replaceable");
        Files.createDirectory(shared);
        Files.setPosixFilePermissions(shared, java.nio.file.attribute.PosixFilePermissions.fromString("rwxrwxrwx"));
        Path confined = shared.resolve("private");
        manager.configDirOverride = Optional.of(confined.toString());
        Method write = TunnelManager.class.getDeclaredMethod("writeConfig", String.class,
                String.class, int.class, String.class, String.class, String.class);
        write.setAccessible(true);
        assertThrows(java.lang.reflect.InvocationTargetException.class, () ->
                write.invoke(manager, "dl-test", "test-key", 51820, "peer", "192.0.2.1:51820", "10.79.0.1"));
        assertFalse(Files.exists(confined));
    }
}
