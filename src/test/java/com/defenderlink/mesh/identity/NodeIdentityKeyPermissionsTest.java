package com.defenderlink.mesh.identity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.*;

class NodeIdentityKeyPermissionsTest {
    @TempDir Path directory;

    @Test
    void keyCreationCannotFollowExistingPrivateKeySymlink() throws Exception {
        Path identityDir = Files.createDirectory(directory.resolve("identity"));
        Path outside = directory.resolve("outside.txt");
        Files.writeString(outside, "sentinel");
        Files.createSymbolicLink(identityDir.resolve("node.key"), outside);
        NodeIdentity identity = new NodeIdentity();
        identity.dataDir = directory.toString();
        assertThrows(RuntimeException.class, identity::init);
        assertEquals("sentinel", Files.readString(outside));
    }

    @Test
    void writableDataParentCannotRedirectIdentityDirectory() throws Exception {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwxrwxrwx"));
        NodeIdentity identity = new NodeIdentity();
        identity.dataDir = directory.toString();
        assertThrows(RuntimeException.class, identity::init);
    }

    @Test
    void loadingAnExistingIdentityRejectsSymlinkedPrivateKey() throws Exception {
        NodeIdentity initial = new NodeIdentity();
        initial.dataDir = directory.toString();
        initial.init();
        Path privatePath = directory.resolve("identity/node.key");
        Path saved = directory.resolve("saved.key");
        Files.move(privatePath, saved);
        Files.createSymbolicLink(privatePath, saved);
        NodeIdentity second = new NodeIdentity();
        second.dataDir = directory.toString();
        assertThrows(RuntimeException.class, second::init);
    }

    @Test
    void loadingRejectsMismatchedPublicKey() throws Exception {
        NodeIdentity first = new NodeIdentity();
        first.dataDir = directory.resolve("first").toString();
        first.init();
        NodeIdentity second = new NodeIdentity();
        second.dataDir = directory.resolve("second").toString();
        second.init();
        Path firstPub = directory.resolve("first/identity/node.pub");
        Files.copy(directory.resolve("second/identity/node.pub"), firstPub,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        assertThrows(RuntimeException.class, first::init);
    }

    @Test
    void loadingRejectsReadablePrivateKey() throws Exception {
        NodeIdentity identity = new NodeIdentity();
        identity.dataDir = directory.toString();
        identity.init();
        Files.setPosixFilePermissions(directory.resolve("identity/node.key"),
                PosixFilePermissions.fromString("rw-r--r--"));
        assertThrows(RuntimeException.class, identity::init);
    }

    @Test
    void generatedPrivateKeyAndDirectoryArePrivate() throws Exception {
        NodeIdentity identity = new NodeIdentity();
        identity.dataDir = directory.toString();
        identity.init();
        Path identityDir = directory.resolve("identity");
        assertEquals(PosixFilePermissions.fromString("rwx------"),
                Files.getPosixFilePermissions(identityDir));
        assertEquals(PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(identityDir.resolve("node.key")));
    }
}
