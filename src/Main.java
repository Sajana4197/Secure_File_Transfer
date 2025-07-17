// Main.java
import java.io.*;
import java.security.PublicKey;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        try {
            // Initialize Receiver
            SecureFileReceiver receiver = new SecureFileReceiver();
            PublicKey receiverPublicKey = receiver.getPublicKey();

            // Initialize Sender with receiver's public key
            SecureFileSender sender = new SecureFileSender(receiverPublicKey);

            // Ask user for file path
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter the path of the file to send: ");
            String filePath = scanner.nextLine().replaceAll("^\"|\"$", "").trim();

            // Use ByteArrayOutputStream for simulation
            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(byteOut);

            sender.prepareMessage(filePath, oos);

            byte[] messageBytes = byteOut.toByteArray();
            ByteArrayInputStream byteIn = new ByteArrayInputStream(messageBytes);
            ObjectInputStream ois = new ObjectInputStream(byteIn);

            receiver.receiveMessage(ois);

            oos.close();
            ois.close();
            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
