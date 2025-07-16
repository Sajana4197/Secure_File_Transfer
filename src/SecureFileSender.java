import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class SecureFileSender {
    private KeyPair senderKeyPair;
    private PublicKey receiverPublicKey;

    // No-argument constructor generates sender's RSA key pair
    public SecureFileSender() throws Exception {
    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        senderKeyPair = keyGen.generateKeyPair();

        System.out.println("[Sender] RSA Key Pair Generated.");
        System.out.println("[Sender] Public Key: " + Base64.getEncoder().encodeToString(senderKeyPair.getPublic().getEncoded()));
        System.out.println("[Sender] Private Key: " + Base64.getEncoder().encodeToString(senderKeyPair.getPrivate().getEncoded()));
    }

    // Set receiver's public key so sender can encrypt AES key
    public void setReceiverPublicKey(PublicKey receiverPublicKey) {
        this.receiverPublicKey = receiverPublicKey;
    }

    public PublicKey getSenderPublicKey() {
        return senderKeyPair.getPublic();
    }

    public byte[] prepareMessage(String filePath) throws Exception {
        if (receiverPublicKey == null) {
            throw new IllegalStateException("Receiver's public key is not set!");
        }

        // Read file bytes
        byte[] fileData = readFile(filePath);
        System.out.println("[Sender] Read file: " + filePath);

        // Generate AES symmetric key
        SecretKey aesKey = CryptoUtils.generateAESKey();
        System.out.println("[Sender] Generated AES Key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

        // Encrypt file with AES key
        byte[] encryptedFile = CryptoUtils.encryptAES(fileData, aesKey);
        System.out.println("[Sender] Encrypted File.");

        // Hash file
        byte[] fileHash = CryptoUtils.hashSHA256(fileData);
        System.out.println("[Sender] File SHA-256 Hash: " + Base64.getEncoder().encodeToString(fileHash));

        // Sign the hash with sender's private RSA key
        byte[] signature = CryptoUtils.sign(fileHash, senderKeyPair.getPrivate());
        System.out.println("[Sender] Signed file hash.");

        // Encrypt AES key with receiver's public RSA key
        byte[] encryptedAESKey = CryptoUtils.encryptRSA(aesKey.getEncoded(), receiverPublicKey);
        System.out.println("[Sender] Encrypted AES key with Receiver's public key.");

        // Generate nonce and timestamp for replay protection
        String nonce = java.util.UUID.randomUUID().toString();
        String timestamp = String.valueOf(System.currentTimeMillis());

        // Serialize message parts into a byte array
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);

        oos.writeObject(encryptedFile);
        oos.writeObject(encryptedAESKey);
        oos.writeObject(fileHash);
        oos.writeObject(signature);
        oos.writeObject(nonce);
        oos.writeObject(timestamp);

        oos.flush();
        byte[] message = baos.toByteArray();
        oos.close();

        System.out.println("[Sender] Message ready. Sending...");
        return message;
    }

    private byte[] readFile(String filePath) throws IOException {
        return java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath));
    }
}
