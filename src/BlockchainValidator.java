import java.io.*;
import java.util.*;

public class BlockchainValidator {
    private static final String CHAIN_FILE = "blockchain.txt";

    public void validateBlockchain() throws Exception {
        List<Block> blocks = loadBlocks();

        boolean valid = true;
        for (int i = 0; i < blocks.size(); i++) {
            Block current = blocks.get(i);
            String recomputedHash = current.computeHash();

            if (!recomputedHash.equals(current.getCurrentHash())) {
                System.out.println("[Validator] ❌ Block " + i + " has invalid hash!");
                valid = false;
            }

            if (i > 0) {
                Block previous = blocks.get(i - 1);
                if (!current.getPreviousHash().equals(previous.getCurrentHash())) {
                    System.out.println("[Validator] ❌ Block " + i + " previous hash does not match Block " + (i - 1));
                    valid = false;
                }
            }
        }

        if (valid) {
            System.out.println("[Validator] Blockchain is valid and intact.");
        } else {
            System.out.println("[Validator] Blockchain has been tampered!");
        }
    }

    private List<Block> loadBlocks() throws Exception {
        List<Block> blocks = new ArrayList<>();
        BufferedReader reader = new BufferedReader(new FileReader(CHAIN_FILE));

        String line;
        StringBuilder blockData = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            if (line.trim().isEmpty()) {
                blocks.add(parseBlock(blockData.toString()));
                blockData.setLength(0);
            } else {
                blockData.append(line).append("\n");
            }
        }

        if (blockData.length() > 0) {
            blocks.add(parseBlock(blockData.toString()));
        }

        reader.close();
        return blocks;
    }

    private Block parseBlock(String blockText) {
        String fileHash = getValue(blockText, "fileHash");
        String timestamp = getValue(blockText, "timestamp");
        String nonce = getValue(blockText, "nonce");
        String previousHash = getValue(blockText, "previousHash");
        String currentHash = getValue(blockText, "currentHash");
        return new Block(fileHash, timestamp, nonce, previousHash, currentHash);
    }

    private String getValue(String block, String field) {
        String pattern = "\"" + field + "\":\\s*\"(.*?)\"";
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(pattern).matcher(block);
        return matcher.find() ? matcher.group(1) : "";
    }
}
