//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Main {
    public static void main(String[] args) throws Exception {
        int keySize = 2048;
        String data = "Witaj, tu Alicja";

        //gen keys
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize); // Specify the desired key size
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        //exchange keys
        Socket socket = new Socket("10.10.107.102",1234);
        System.out.println("AL: Connected!");
        OutputStream outputStream = socket.getOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        System.out.println("AL: Sending public key");
        objectOutputStream.writeObject(publicKey);

        ServerSocket serverSocket = new ServerSocket(1235);
        System.out.println("AL: Waiting for client to connect...");
        boolean connected = false;
        Socket socketClient = null;
        while (!connected) {
            try{
                socketClient = serverSocket.accept();
                connected = true;
            }
            catch(IOException e){
                System.out.print("Nie udało się");
                connected = false;
            }
        }
        System.out.println("AL: Got connection");
        InputStream inputStream = socketClient.getInputStream();
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        PublicKey publicKey2 = (PublicKey) objectInputStream.readObject();
        System.out.println("AL: Got key");

        //hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedData = digest.digest(data.getBytes(StandardCharsets.UTF_8));

        //sign
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hashedData);
        byte[] signedHash = signature.sign();

        //send
        System.out.println("AL: Sending msg");
        objectOutputStream.writeObject(signedHash);
        objectOutputStream.writeObject(data);

        //get message
        System.out.println("AL: Received msg");
        byte[] receivedSignedHash = (byte[]) objectInputStream.readObject();
        String dataReceived = (String) objectInputStream.readObject();

        //verify
        Signature signature2 = Signature.getInstance("SHA256withRSA");
        signature2.initVerify(publicKey2);
        signature2.update(digest.digest(dataReceived.getBytes(StandardCharsets.UTF_8)));
        boolean isValid = signature2.verify(receivedSignedHash);
        System.out.println("AL: Message verified: " + isValid);
        System.out.println("AL: Message: " + dataReceived);
        System.out.println("AL: Message signed: " + receivedSignedHash);

        socket.close();
        serverSocket.close();
    }
}