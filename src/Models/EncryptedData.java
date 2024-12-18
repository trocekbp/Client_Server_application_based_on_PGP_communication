package Models;

import java.io.Serializable;

public class EncryptedData implements Serializable {
    private String Login;
    private byte[] encryptedSecretKey;

    // Konstruktor
    public EncryptedData(String Login, byte[] encryptedSecretKey) {
        this.Login = Login;
        this.encryptedSecretKey = encryptedSecretKey;
    }

    // Gettery i settery
    public String getLogin() {
        return Login;
    }

    public byte[] getEncryptedSecretKey() {
        return encryptedSecretKey;
    }
}
