//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.

import Models.EncryptedData;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ConnectException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Random;
import java.util.Scanner;

public class Client implements SecurityUtils {
    //encrypted data
    public static void main(String[] args) throws Exception {
        try {
            // Przygotowanie danych
            EncryptedData encryptedData;
            Random random = new Random();
            int noun;
            int decryptedNoun;
            byte[] encryptedNoun;
            KeyPair keyPair = SecurityUtils.generateKeyPair();
            String response;
            //klucz do szyfrowania wiadomości po zalogowaniu
            SecretKey secretKey = SecurityUtils.generateSecretKey();
            // Połączenie z serwerem
            Socket socket = new Socket("localhost", 1234);
            System.out.println("Client: Connected!");

            // Strumienie do wysyłania/odbierania danych
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

            // Wysłanie publicznego klucza klienta
            System.out.println("Client: Sending public key");
            objectOutputStream.writeObject(keyPair.getPublic());

            // Odbiór publicznego klucza serwera
            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
            PublicKey publicKeyApi = (PublicKey) objectInputStream.readObject();
            System.out.println("Client: Received server's public key");

            //#Weryfikacja użytkownika#
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
                //#Weryfikacja Api#
                // Szyfrowanie liczby "noun" z użyciem publicznego klucza serwera
                noun = random.nextInt();
                encryptedNoun = SecurityUtils.encryptNoun(noun, publicKeyApi);
                objectOutputStream.writeObject(encryptedNoun);
                objectOutputStream.flush();

                // Odbiór odpowiedzi (odszyfrowanej liczby)
                decryptedNoun =  objectInputStream.readInt();
                // Weryfikacja odpowiedzi
                if (decryptedNoun == noun) {
                    System.out.println("Client: Two way verification ended successfully!");
                    response = "OK";
                    objectOutputStream.writeObject(response);
                    objectOutputStream.flush();
                    response = new String();
                    //wszystko jest ok przechodzimy do wyświetlenia menu
                } else {
                    System.out.println("Client: Two way verification Failed! (Error at api verification)");
                    System.exit(1);
                }

            }
            while (true) {
                try {
                    System.out.println("Client: Choose option:");
                    System.out.println("1 -> Registration");
                    System.out.println("2 -> Login");
                    System.out.println("3 -> Exit");
                    Scanner scanner = new Scanner(System.in);

                    int choice = scanner.nextInt();
                    scanner.nextLine();

                    switch (choice) {
                        case 1:
                            objectOutputStream.writeInt(1);
                            objectOutputStream.flush();

                            System.out.println("Podaj login: ");
                            var loginReg = scanner.nextLine();
                            var encryptedLoginReg = SecurityUtils.encryptLogin(loginReg, publicKeyApi);
                            objectOutputStream.writeObject(encryptedLoginReg);

                            var responseFromApi = objectInputStream.readObject().toString();
                            if (responseFromApi.equals("OK")) {
                                System.out.println("Client: Registration successful!");
                                response = new String(); //czyszczenie response
                            } else {
                                System.out.println("Client: Registration failed.");
                            }
                            break;
                        case 2:
                            objectOutputStream.writeInt(2);
                            objectOutputStream.flush();
                            System.out.println("Podaj login: ");
                            var login = scanner.nextLine();

                           //Generuje klucz sesji AES (AES).
                            //Szyfruje ten klucz swoim kluczem publicznym API Gateway: K+API(AES).
                            var encryptedSecretKey = SecurityUtils.encryptKey(secretKey, publicKeyApi);
                            //wiadomość = login | Api+(AES)
                            encryptedData = new EncryptedData(login, encryptedSecretKey);
                            //Wysyła do API Gateway wiadomość zawierającą login użytkownika (jas) oraz zaszyfrowany klucz AES:
                            objectOutputStream.writeObject(encryptedData);
                            objectOutputStream.flush();

                            //test czy został znaleziony user w bazie danych
                            response = objectInputStream.readObject().toString();
                            if (response.equals("OK")) {
                                response = new String(); //czyszczenie response
                            }else{
                                System.out.println(response);
                            }

                            //Otrzymuje i odszyfrowuje Odszyfrowuje nonce swoim kluczem prywatnym K-u:
                            var encryptedNonce = (byte[])objectInputStream.readObject();
                            int nonce = SecurityUtils.decryptNoun(encryptedNonce, keyPair.getPrivate());
                            //Wysyła odszyfrowany nonce z powrotem do API Gateway:
                            objectOutputStream.writeInt(nonce);
                            objectOutputStream.flush();

                            //odbiera odpowiedź API
                            response = objectInputStream.readObject().toString();
                            if (response.equals("OK")) {
                                System.out.println("Client: Login successful!");

                            }else{
                                System.out.println("Client: Login failed.");
                            }
                            break;
                        case 3:
                            System.exit(0);
                            break;

                        default:
                            System.out.println("Client: Invalid option.");
                            break;
                    }
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
            }
        } catch (ConnectException e){
            //w przypadku wyłączonego API
            System.out.println("Połączenie odrzucone: błąd połączenia");
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}

