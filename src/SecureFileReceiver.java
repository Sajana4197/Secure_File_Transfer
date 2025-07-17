import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.*;

public class SecureFileReceiver {
    private PrivateKey receiverPrivateKey;
    private PublicKey receiverPublicKey;
    private UUID flowId;

    public SecureFileReceiver() throws Exception {
        generateRSAKeys();
    }

    private void generateRSAKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        receiverPrivateKey = keyPair.getPrivate();
        receiverPublicKey = keyPair.getPublic();
        System.out.println("[Receiver] RSA Key Pair Generated.");
        System.out.println("[Receiver] Public Key: " + Base64.getEncoder().encodeToString(receiverPublicKey.getEncoded()));
        System.out.println("[Receiver] Private Key: " + Base64.getEncoder().encodeToString(receiverPrivateKey.getEncoded()));
    }

    public PublicKey getPublicKey() {
        return receiverPublicKey;
    }

    public void receiveMessage(ObjectInputStream ois) throws Exception {
        System.out.println("[Receiver] Message received. Processing...");
        byte[] encryptedFile = (byte[]) ois.readObject();
        byte[] encryptedAESKey = (byte[]) ois.readObject();
        byte[] fileHash = (byte[]) ois.readObject();
        byte[] signature = (byte[]) ois.readObject();
        UUID nonce = (UUID) ois.readObject();
        long timestamp = ois.readLong();
        PublicKey senderPublicKey = (PublicKey) ois.readObject();
        String flowIdString = (String) ois.readObject();
        this.flowId = UUID.fromString(flowIdString);

        System.out.println("[Receiver] Nonce: " + nonce);
        System.out.println("[Receiver] Timestamp: " + timestamp);
        System.out.println("[Receiver] Flow ID: " + flowId);

        // Decrypt AES key
        byte[] aesKeyBytes = CryptoUtils.decryptRSA(encryptedAESKey, receiverPrivateKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");
        System.out.println("[Receiver] Decrypted AES key.");

        // Decrypt file
        byte[] fileContent = CryptoUtils.decryptAES(encryptedFile, aesKey);
        System.out.println("[Receiver] Decrypted file content.");

        // Verify hash
        byte[] computedHash = CryptoUtils.hashSHA256(fileContent);
        System.out.println("[Receiver] Computed hash: " + Base64.getEncoder().encodeToString(computedHash));
        if (Arrays.equals(fileHash, computedHash)) {
            System.out.println("[Receiver] File hash matches ✓");
        } else {
            System.out.println("[Receiver] File hash mismatch ✗");
        }

        // Verify signature
        boolean isValid = CryptoUtils.verifySignature(fileHash, signature, senderPublicKey);
        System.out.println("[Receiver] Signature valid? " + isValid);

        // Save file
        Files.write(Paths.get("received_file.txt"), fileContent);
        System.out.println("[Receiver] File saved: received_file.txt");

        // Log to blockchain
        BlockchainLogger.logBlock(Base64.getEncoder().encodeToString(fileHash), timestamp, nonce.toString(), flowId.toString());
    }
}
