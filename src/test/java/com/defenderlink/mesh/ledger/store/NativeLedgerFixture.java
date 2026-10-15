package com.defenderlink.mesh.ledger.store;

import com.defenderlink.mesh.identity.NodeIdentity;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.HexFormat;

/** Real RocksDB and signed blocks; no HTTP, gossip or consensus authenticity claim. */
public final class NativeLedgerFixture implements AutoCloseable {
    public final LedgerStore store = new LedgerStore();
    public final NodeIdentity identity;

    public NativeLedgerFixture(Path directory) throws Exception {
        KeyPair keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encoded = keys.getPublic().getEncoded();
        String nodeId = HexFormat.of().formatHex(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length));
        identity = new NodeIdentity() {
            @Override public String getNodeId() { return nodeId; }
            @Override public byte[] sign(byte[] data) {
                try {
                    Signature signer = Signature.getInstance("Ed25519");
                    signer.initSign(keys.getPrivate()); signer.update(data); return signer.sign();
                } catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
            }
        };
        store.identity = identity;
        store.ledgerDataDir = directory.toString();
        store.maxFreeNodes = 3;
        store.onStart(null);
    }
    @Override public void close() { store.onStop(null); }
}
