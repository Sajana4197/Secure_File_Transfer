import java.io.*;
import java.util.*;

public class BlockchainLogger {
    private static final String CHAIN_FILE = "blockchain.txt";

    public void logBlock(String fileHash, String timestamp, String nonce) throws Exception {
        String prevHash = getLastBlockHash();
        Block newBlock = new Block(fileHash, timestamp, nonce, prevHash);

        FileWriter fw = new FileWriter(CHAIN_FILE, true);
        fw.write(newBlock.toString() + "\n\n");
        fw.close();

        // Print full block to console
        System.out.println("[Blockchain] Block successfully logged:");
        System.out.println(newBlock.toString());
    }

    private String getLastBlockHash() throws Exception {
        File file = new File(CHAIN_FILE);
        if (!file.exists() || file.length() == 0)
            return "0";  // Genesis block previous hash

        List<String> lines = java.nio.file.Files.readAllLines(file.toPath());
        for (int i = lines.size() - 1; i >= 0; i--) {
            if (lines.get(i).trim().startsWith("\"currentHash\":")) {
                return lines.get(i).split(":")[1].trim().replace("\"", "").replace(",", "");
            }
        }
        return "0";
    }
}
