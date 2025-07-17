import javax.crypto.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public class SecureFileSender {
    private PublicKey receiverPublicKey;
    private PrivateKey senderPrivateKey;
    private PublicKey senderPublicKey;
    private UUID flowId;

    public SecureFileSender(PublicKey receiverPublicKey) throws Exception {
        this.receiverPublicKey = receiverPublicKey;
        generateRSAKeys();
        this.flowId = UUID.randomUUID();
        System.out.println("[Sender] Flow ID: " + flowId);
    }

    public PublicKey getPublicKey() {
        return senderPublicKey;
    }

    public PrivateKey getPrivateKey() {
        return senderPrivateKey;
    }

    private void generateRSAKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        senderPrivateKey = keyPair.getPrivate();
        senderPublicKey = keyPair.getPublic();
        System.out.println("[Sender] RSA Key Pair Generated.");
        System.out.println("[Sender] Public Key: " + Base64.getEncoder().encodeToString(senderPublicKey.getEncoded()));
        System.out.println("[Sender] Private Key: " + Base64.getEncoder().encodeToString(senderPrivateKey.getEncoded()));
    }

    public void prepareMessage(String filePath, ObjectOutputStream oos) throws Exception {
        byte[] fileContent = readFile(filePath);
        System.out.println("[Sender] Read file: " + filePath);

        // Generate AES Key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();
        System.out.println("[Sender] Generated AES Key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

        // Encrypt the file
        byte[] encryptedFile = CryptoUtils.encryptAES(fileContent, aesKey);
        System.out.println("[Sender] Encrypted File.");

        // Compute hash
        byte[] fileHash = CryptoUtils.hashSHA256(fileContent);
        System.out.println("[Sender] File SHA-256 Hash: " + Base64.getEncoder().encodeToString(fileHash));

        // Sign the hash
        byte[] signature = CryptoUtils.signData(fileHash, senderPrivateKey);
        System.out.println("[Sender] Signed file hash.");

        // Encrypt AES key with receiver's public key
        byte[] encryptedAESKey = CryptoUtils.encryptRSA(aesKey.getEncoded(), receiverPublicKey);
        System.out.println("[Sender] Encrypted AES key with Receiver's public key.");

        // Nonce & Timestamp
        UUID nonce = UUID.randomUUID();
        long timestamp = System.currentTimeMillis();

        // Send data
        System.out.println("[Sender] Message ready. Sending...");
        oos.writeObject(encryptedFile);
        oos.writeObject(encryptedAESKey);
        oos.writeObject(fileHash);
        oos.writeObject(signature);
        oos.writeObject(nonce);
        oos.writeLong(timestamp);
        oos.writeObject(senderPublicKey);
        oos.writeObject(flowId.toString());
        oos.flush();
    }

    private byte[] readFile(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }
}