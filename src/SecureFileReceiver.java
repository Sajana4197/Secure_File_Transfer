import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class SecureFileReceiver {
    private KeyPair receiverKeyPair;
    private PublicKey senderPublicKey;

    // Constructor accepts sender's public key for signature verification
    public SecureFileReceiver(PublicKey senderPublicKey) throws Exception {
        this.senderPublicKey = senderPublicKey;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        receiverKeyPair = keyGen.generateKeyPair();

        System.out.println("[Receiver] RSA Key Pair Generated.");
        System.out.println("[Receiver] Public Key: " + Base64.getEncoder().encodeToString(receiverKeyPair.getPublic().getEncoded()));
        System.out.println("[Receiver] Private Key: " + Base64.getEncoder().encodeToString(receiverKeyPair.getPrivate().getEncoded()));
    }

    public PublicKey getPublicKey() {
        return receiverKeyPair.getPublic();
    }

    public void receiveMessage(byte[] message) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(message);
        ObjectInputStream ois = new ObjectInputStream(bais);

        byte[] encryptedFile = (byte[]) ois.readObject();
        byte[] encryptedAESKey = (byte[]) ois.readObject();
        byte[] fileHash = (byte[]) ois.readObject();
        byte[] signature = (byte[]) ois.readObject();
        String nonce = (String) ois.readObject();
        String timestamp = (String) ois.readObject();
        ois.close();

        System.out.println("[Receiver] Message received. Processing...");
        System.out.println("[Receiver] Nonce: " + nonce);
        System.out.println("[Receiver] Timestamp: " + timestamp);

        // Decrypt AES key with receiver's private RSA key
        byte[] aesKeyBytes = CryptoUtils.decryptRSA(encryptedAESKey, receiverKeyPair.getPrivate());
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");
        System.out.println("[Receiver] Decrypted AES key.");

        // Decrypt file with AES key
        byte[] decryptedFile = CryptoUtils.decryptAES(encryptedFile, aesKey);
        System.out.println("[Receiver] Decrypted file content.");

        // Compute hash of decrypted file
        byte[] computedHash = CryptoUtils.hashSHA256(decryptedFile);
        System.out.println("[Receiver] Computed hash: " + Base64.getEncoder().encodeToString(computedHash));

        // Compare received hash and recomputed hash
        if (MessageDigest.isEqual(fileHash, computedHash)) {
            System.out.println("[Receiver] File hash matches ✓");
        } else {
            System.out.println("[Receiver] File hash mismatch ✗ — Possible tampering");
        }

        // Verify signature with sender's public key
        boolean verified = CryptoUtils.verify(computedHash, signature, senderPublicKey);
        System.out.println("[Receiver] Signature valid? " + verified);

        // Save the decrypted file locally
        FileOutputStream fos = new FileOutputStream("received_file.txt");
        fos.write(decryptedFile);
        fos.close();
        System.out.println("[Receiver] File saved: received_file.txt");

        // Log to blockchain
        BlockchainLogger logger = new BlockchainLogger();
        logger.logBlock(
            Base64.getEncoder().encodeToString(computedHash), 
            timestamp,
            nonce
        );

    }
}
