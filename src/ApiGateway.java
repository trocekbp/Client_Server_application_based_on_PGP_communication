import Models.EncryptedData;
import Models.User;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ApiGateway implements SecurityUtils {
    //db
    private static List<User> users_list = new ArrayList<User>();
    public static void main(String[] args) throws Exception {
        // Przygotowanie danych
        int keySize = 2048;
        int noun;
        KeyPair keyPair = SecurityUtils.generateKeyPair();
        User tmp_user;
        Random random = new Random();
        PublicKey userPK;
        String response;

        // Nasłuchiwanie na porcie 1234
        ServerSocket serverSocket = new ServerSocket(1234);
        System.out.println("Server: Waiting for client to connect...");
        Socket socketClient = serverSocket.accept();
        System.out.println("Server: Got connection");

        // Strumienie do odbierania/wysyłania danych
        InputStream inputStream = socketClient.getInputStream();
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        OutputStream outputStream = socketClient.getOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

        // Odbiór publicznego klucza klienta
        PublicKey publicKeyClient = (PublicKey) objectInputStream.readObject();
        System.out.println("Server: Received client's public key");

        // Wysłanie publicznego klucza serwera
        objectOutputStream.writeObject(keyPair.getPublic());
        objectOutputStream.flush();

        //#weryfikacja użytkownika#
        noun = random.nextInt();
        byte[] encryptedNoun = SecurityUtils.encryptNoun(noun, publicKeyClient);
        objectOutputStream.writeObject(encryptedNoun);
        objectOutputStream.flush();

        // Odbiór odpowiedzi (odszyfrowanej liczby)
        int decryptedNoun =  objectInputStream.readInt();
        // Weryfikacja odpowiedzi
        if (decryptedNoun == noun) {
            System.out.println("Server[Client veryfication]: Verification successful!");
            response = "OK";
            objectOutputStream.writeObject(response);
            response = new String(); //czyszczenie Stringa

            //#Weryfikacja api gateway#
            //odbiór zaszyfrowanej liczby noun
            encryptedNoun = (byte[]) objectInputStream.readObject();
            //deszyfrowanie liczby noun
            decryptedNoun = SecurityUtils.decryptNoun(encryptedNoun, keyPair.getPrivate());
            //odesłanie odszyfrowanej liczby
            objectOutputStream.writeInt(decryptedNoun);
            objectOutputStream.flush();
            //czekamy na odpowiedź czy użytkownik został uwierzytelniony
            response = (String) objectInputStream.readObject();
            if (response.equals("OK")){
                //wszystko jest okey
                System.out.println("Server[Client veryfication]: Two way verification ended successfully!");
            }else{
                System.out.println("Server[Client veryfication]: Two way verification failed!");
            }

        } else {
            System.out.println("Server[Client veryfication]: Verification failed.");
            response = "verification failed";
            objectOutputStream.writeObject(response);
            response = new String(); //czyszczenie Stringa
        }

        //po pomyślnej weryfikacji
        while (true) {
            try {
                // Oczekiwanie na wybór opcji
                int choice = objectInputStream.readInt();
                System.out.println("Serwer[Registration]: Otrzymano wybór klienta -> " + choice);
                switch (choice) {
                    case 1:
                        byte[] encryptedLoginReg = (byte[]) objectInputStream.readObject();
                        System.out.println("Server[Registration]: Received client's encrypted login");
                        //decrypting user login with Apis private key
                        String loginReg = SecurityUtils.decryptLogin(encryptedLoginReg, keyPair.getPrivate());

                        //zapisywanie loginy odszyfrowanego na obecną chwilę
                        System.out.println("Server[Registration]: Decrypted login:"+loginReg+"\n");
                        //saving users login + public key to database
                        tmp_user = new User(loginReg, publicKeyClient);
                        users_list.add(tmp_user);
                        response = "OK";
                        objectOutputStream.writeObject(response);
                        break;
                    case 2:
                        EncryptedData encryptedData = (EncryptedData)objectInputStream.readObject();
                        System.out.println("[Login]Server: Received client's encrypted data");

                        //#Registration odnajduje rekord dla użytkownika jas, i odsyła do API Gateway klucz publiczny uzytkownika#
                            //Szukanie użytkownika w bazie danych
                        String login = encryptedData.getLogin();
                        tmp_user = findByLogin(login);
                        if (tmp_user != null) {
                            System.out.println("[Login]Server: User is in database");
                            String respone = "OK";
                            objectOutputStream.writeObject(respone);
                            //Registration zwraca klucz publiczny użytkownika
                            userPK = tmp_user.getPublicKey();

                        }else{
                            System.out.println("[Login]Server: User isn't in database");
                            String respone = "Invalid login";
                            objectOutputStream.writeObject(respone);
                            break;
                        }
                        //Odszyfrowuje K+API(AES) swoim kluczem prywatnym K
                        var encryptedSecretKey = encryptedData.getEncryptedSecretKey();
                        SecretKey cliSecretKey = SecurityUtils.decryptKey(encryptedSecretKey, keyPair.getPrivate());
                        System.out.println("[Login]Server: SecretKey is decrypted");
                        //#Weryfikacja tożsamości użytkownika za pomocą nonce#

                        //Api generuje losowy nonce (unikalny ciąg znaków używany do weryfikacji).
                        int nonce = random.nextInt();
                        //Szyfruje nonce kluczem publicznym użytkownika:
                        var encryptedNonce = SecurityUtils.encryptNoun(nonce, userPK);
                        //Wysyła zaszyfrowany nonce do CLI:
                        objectOutputStream.writeObject(encryptedNonce);
                        System.out.println("[Login]Server: Nonce is written");
                        //Porównuje otrzymany nonce z wygenerowanym wcześniej.
                        int cliNonce = objectInputStream.readInt();
                        System.out.println("[Login]Server: Get nonce from cli");
                        if(nonce == cliNonce){
                            //Jeśli nonce się zgadza, CLI jest uwierzytelnione.
                            System.out.println("[Login]Server: Client login successful");
                            response = "OK";
                            objectOutputStream.writeObject(response);
                        }
                        else{
                            System.out.println("[Login]Server: Client login unsuccessful");
                            response = "ERROR";
                            objectOutputStream.writeObject(response);
                        }
                        break;

                    default:
                        break;
                }
            } catch (EOFException e) {
                System.out.println("[Login]Klient zakończył połączenie.");
                break;
            } catch (Exception e) {
                System.out.println("[Login]Błąd: " + e.getMessage());
            }

        }

    }
    public static User findByLogin(String login) {
        return users_list.stream()
                .filter(user -> user.getLogin().equals(login))
                .findFirst()
                .orElse(null);
    }
}