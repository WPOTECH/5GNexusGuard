package com.defenderlink.mesh.ledger.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/**
 * A block in the 5GNexusGuard Merkle chain.
 *
 * Each block contains:
 * - An ordered list of ledger entries (node registrations, service changes)
 * - A SHA-256 hash of the previous block (forming the chain)
 * - The block author's Ed25519 signature
 * - A Merkle root of the entries for efficient verification
 *
 * Blocks are created by the current Raft leader and replicated to all nodes.
 * Any node can verify the chain independently by checking:
 * 1. Each block's hash matches SHA-256(block_data + prev_hash)
 * 2. Each entry's signature is valid against the author's registered public key
 * 3. The chain is unbroken (each prev_hash matches the previous block's hash)
 */
public record Block(
        long index,                 // block number (0 = genesis)
        String hash,                // SHA-256 hex of this block
        String prevHash,            // SHA-256 hex of previous block
        String merkleRoot,          // Merkle root of entries
        String authorNodeId,        // Ed25519 public key hex of block author (Raft leader)
        byte[] authorSignature,     // Ed25519 signature over (index + prevHash + merkleRoot + timestamp)
        List<LedgerEntry> entries,
        Instant timestamp
) {

    /** Genesis block — the root of the chain */
    public static Block genesis() {
        String genesisHash = sha256("defenderlink-genesis-block-v1");
        return new Block(
                0, genesisHash, "0000000000000000000000000000000000000000000000000000000000000000",
                genesisHash, "genesis", new byte[64], List.of(), Instant.now()
        );
    }

    /** Compute the hash of this block (for chain validation) */
    public static String computeHash(long index, String prevHash, String merkleRoot,
                                      String authorNodeId, Instant timestamp,
                                      List<LedgerEntry> entries) {
        StringBuilder sb = new StringBuilder();
        sb.append(index).append(prevHash).append(merkleRoot)
          .append(authorNodeId).append(timestamp.toEpochMilli());
        for (LedgerEntry e : entries) {
            sb.append(e.type()).append(e.authorNodeId()).append(e.timestamp().toEpochMilli());
        }
        return sha256(sb.toString());
    }

    /** Compute Merkle root of entries */
    public static String computeMerkleRoot(List<LedgerEntry> entries) {
        if (entries.isEmpty()) return sha256("empty");

        List<String> hashes = entries.stream()
                .map(e -> sha256(e.type() + e.authorNodeId() + e.timestamp().toEpochMilli()))
                .toList();

        return buildMerkleTree(hashes);
    }

    /** Get the bytes that the block author signs */
    @JsonIgnore
    public byte[] getSignableBytes() {
        String signable = index + prevHash + merkleRoot + authorNodeId + timestamp.toEpochMilli();
        return signable.getBytes(StandardCharsets.UTF_8);
    }

    /** Validate block hash consistency */
    @JsonIgnore
    public boolean isHashValid() {
        String expected = computeHash(index, prevHash, merkleRoot, authorNodeId, timestamp, entries);
        return expected.equals(hash);
    }

    /** Validate chain link (this block's prevHash matches parent's hash) */
    @JsonIgnore
    public boolean isChainedTo(Block parent) {
        return prevHash.equals(parent.hash()) && index == parent.index() + 1;
    }

    // --- Internal ---

    private static String buildMerkleTree(List<String> hashes) {
        if (hashes.size() == 1) return hashes.getFirst();

        List<String> nextLevel = new java.util.ArrayList<>();
        for (int i = 0; i < hashes.size(); i += 2) {
            if (i + 1 < hashes.size()) {
                nextLevel.add(sha256(hashes.get(i) + hashes.get(i + 1)));
            } else {
                nextLevel.add(hashes.get(i)); // odd leaf promotes
            }
        }
        return buildMerkleTree(nextLevel);
    }

    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
