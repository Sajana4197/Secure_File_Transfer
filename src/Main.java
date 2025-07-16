import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        // Ask user for input file path
        System.out.print("Enter the path of the file to send: ");
        String filePath = scanner.nextLine().replaceAll("^\"|\"$", "").trim();

        // Sender and Receiver setup
        SecureFileSender sender = new SecureFileSender();
        SecureFileReceiver receiver = new SecureFileReceiver(sender.getSenderPublicKey());

        sender.setReceiverPublicKey(receiver.getPublicKey());

        // Send and receive file
        byte[] message = sender.prepareMessage(filePath);
        receiver.receiveMessage(message);

        // Validate blockchain
        BlockchainValidator validator = new BlockchainValidator();
        validator.validateBlockchain();

        scanner.close();
    }
}
