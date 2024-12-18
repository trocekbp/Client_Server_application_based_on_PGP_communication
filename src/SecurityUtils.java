import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public interface SecurityUtils {
    // ### RSA ###
     static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Specify the desired key size
        return keyGen.generateKeyPair();
    }
    //szyfrowanie losową liczbę (przyjmuje int i klucz publiczny)
    static byte[] encryptNoun(int noun, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptetNoun = cipher.doFinal(Integer.toString(noun).getBytes());
        return encryptetNoun;
    }

    //tworze metode co przyjmuje bajty i klucz prywatny
     static int decryptNoun(byte[] encryptedNoun, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte [] decryptedNoun = cipher.doFinal(encryptedNoun);
        int noun = Integer.parseInt(new String(decryptedNoun));
        return noun;
    }

    static byte[] encryptLogin(String login, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptetLogin = cipher.doFinal(login.getBytes());
        return encryptetLogin;
    }
    static String decryptLogin(byte[] encryptedLogin, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte [] decryptedLogin = cipher.doFinal(encryptedLogin);
        //tera robimy konwersję aby nie otrzymać adresu pamięci zamiast loginu
        String login = new String(decryptedLogin);
        return login;
    }
    //szyfrowanie klucza symetrycznego kluczem publicznym odbiorcy
    public static byte[] encryptKey(SecretKey secretKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }
    //odszyfrowywanie klucza symetrycznego kluczem prywatnym odbiorcy
    public static SecretKey decryptKey(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
    }

    // ### AES ###

    //Klucz z szyfrowaniem AES - do przesyłania wszelkich wiadomości po zalogowaniu
    //generowanie klucza symetrycznego do wysyłania wiadomości
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    //szyfrowanie kluczem symetrycznym (tu i tu)
    public static byte[] encrypt(byte[] dataToEncrypt, SecretKey secretKey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(dataToEncrypt);
    }

    //odszyfrowywanie za pomocą klucza symetrycznego (nad i odb)
    public static byte[] decrypt(byte[] dataToDecrypt, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(dataToDecrypt);
    }
}




















// Kroki logowania
//Krok 1: Inicjalizacja logowania przez CLI
//CLI:
//Generuje klucz sesji AES (AES).
//Szyfruje ten klucz swoim kluczem publicznym API Gateway: K+API(AES).
//Wysyła do API Gateway wiadomość zawierającą login użytkownika (jas) oraz zaszyfrowany klucz AES:
//        {login: jas, encryptedAES: K+API(AES)}.

//Krok 2: Pobranie klucza publicznego użytkownika z mikroserwisu Registration
//API Gateway:
//Odbiera wiadomość od CLI i przesyła login jas do mikroserwisu Registration:
//        {login: jas}.
//Registration zwraca klucz publiczny użytkownika jas: K+u.

//Krok 3: Odszyfrowanie klucza AES
//API Gateway:
//Odszyfrowuje K+API(AES) swoim kluczem prywatnym K-API:
//AES = K-API(K+API(AES)).

//Krok 4: Weryfikacja tożsamości użytkownika za pomocą nonce
//API Gateway:
//
//Generuje losowy nonce (unikalny ciąg znaków używany do weryfikacji).
//Szyfruje nonce kluczem publicznym użytkownika:
//K+u(nonce).
//Wysyła zaszyfrowany nonce do CLI:
//        {nonceEncrypted: K+u(nonce)}.
//CLI:
//
//Odszyfrowuje nonce swoim kluczem prywatnym K-u:
//nonce = K-u(K+u(nonce)).
//Wysyła odszyfrowany nonce z powrotem do API Gateway:
//        {nonce}.
//API Gateway:
//
//Porównuje otrzymany nonce z wygenerowanym wcześniej.
//Jeśli nonce się zgadza, CLI jest uwierzytelnione.
//Krok 5: Ustanowienie sesji z kluczem AES
//Po pomyślnej weryfikacji:
//API Gateway i CLI korzystają z ustalonego klucza symetrycznego AES do dalszej komunikacji.
//Wszystkie kolejne wiadomości są szyfrowane za pomocą AES.