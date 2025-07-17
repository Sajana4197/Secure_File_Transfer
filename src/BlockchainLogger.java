// BlockchainLogger.java
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class BlockchainLogger {

    // Simple blockchain block structure
    static class Block {
        String fileHash;
        long timestamp;
        String nonce;
        String flowId;
        String previousHash;
        String currentHash;

        Block(String fileHash, long timestamp, String nonce, String flowId, String previousHash, String currentHash) {
            this.fileHash = fileHash;
            this.timestamp = timestamp;
            this.nonce = nonce;
            this.flowId = flowId;
            this.previousHash = previousHash;
            this.currentHash = currentHash;
        }
    }

    private static List<Block> blockchain = new ArrayList<>();

    // Method to log a new block with flowId included
    public static void logBlock(String fileHash, long timestamp, String nonce, String flowId) {
        String previousHash = blockchain.isEmpty() ? "0" : blockchain.get(blockchain.size() - 1).currentHash;

        // Prepare block data string for hashing
        String dataToHash = fileHash + timestamp + nonce + flowId + previousHash;
        String currentHash = sha256(dataToHash);

        Block newBlock = new Block(fileHash, timestamp, nonce, flowId, previousHash, currentHash);
        blockchain.add(newBlock);

        System.out.println("[Blockchain] Block successfully logged:");
        System.out.println("{");
        System.out.println("  \"fileHash\": \"" + fileHash + "\",");
        System.out.println("  \"timestamp\": \"" + timestamp + "\",");
        System.out.println("  \"nonce\": \"" + nonce + "\",");
        System.out.println("  \"flowId\": \"" + flowId + "\",");
        System.out.println("  \"previousHash\": \"" + previousHash + "\",");
        System.out.println("  \"currentHash\": \"" + currentHash + "\"");
        System.out.println("}");
    }

    // SHA-256 hashing helper method
    private static String sha256(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(data.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if(hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
