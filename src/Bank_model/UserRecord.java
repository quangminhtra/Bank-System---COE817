package Bank_model;

public class UserRecord {
    private final String username;
    private final byte[] salt;
    private final int iterations;
    private final byte[] psk;
    private double balance;

    public UserRecord(String username, byte[] salt, int iterations, byte[] psk, double balance) {
        this.username = username;
        this.salt = salt;
        this.iterations = iterations;
        this.psk = psk;
        this.balance = balance;
    }

    public String getUsername() {
        return username;
    }

    public byte[] getSalt() {
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    public byte[] getPsk() {
        return psk;
    }

    public synchronized double getBalance() {
        return balance;
    }

    public synchronized void setBalance(double balance) {
        this.balance = balance;
    }
}
