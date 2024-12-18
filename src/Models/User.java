package Models;

import java.security.PublicKey;

public class User {
    private int id;
    private String login;     //encrypted login
    private PublicKey publicKey;

    public User(String login, PublicKey publicKey) {
        this.login = login;
        this.publicKey = publicKey;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", login='" + login + '\'' +
                ", publicKey='" + publicKey + '\'' +
                '}';
    }
}
