import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

public class Block {
    private String fileHash;
    private String timestamp;
    private String nonce;
    private String previousHash;
    private String currentHash;

    // Main constructor (used when creating new blocks)
    public Block(String fileHash, String timestamp, String nonce, String previousHash) {
        this.fileHash = fileHash;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.previousHash = previousHash;
        this.currentHash = computeHash();
    }

    // Constructor used by BlockchainValidator (provides stored hash)
    public Block(String fileHash, String timestamp, String nonce, String previousHash, String currentHash) {
        this.fileHash = fileHash;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.previousHash = previousHash;
        this.currentHash = currentHash;
    }

    public String computeHash() {
        try {
            String data = fileHash + timestamp + nonce + previousHash;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error computing block hash", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public String getCurrentHash() {
        return currentHash;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public String toString() {
        return "{\n" +
               "  \"fileHash\": \"" + fileHash + "\",\n" +
               "  \"timestamp\": \"" + timestamp + "\",\n" +
               "  \"nonce\": \"" + nonce + "\",\n" +
               "  \"previousHash\": \"" + previousHash + "\",\n" +
               "  \"currentHash\": \"" + currentHash + "\"\n" +
               "}";
    }
}
