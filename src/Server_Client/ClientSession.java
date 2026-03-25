package Server_Client;

import javax.crypto.SecretKey;

public class ClientSession {
    private final String username;
    private final String atmId;
    private final SecretKey encryptionKey;
    private final SecretKey macKey;
    private long expectedClientSequence = 1;
    private long serverSequence = 1;

    public ClientSession(String username, String atmId, SecretKey encryptionKey, SecretKey macKey) {
        this.username = username;
        this.atmId = atmId;
        this.encryptionKey = encryptionKey;
        this.macKey = macKey;
    }

    public String getUsername() {
        return username;
    }

    public String getAtmId() {
        return atmId;
    }

    public SecretKey getEncryptionKey() {
        return encryptionKey;
    }

    public SecretKey getMacKey() {
        return macKey;
    }

    public synchronized long getExpectedClientSequence() {
        return expectedClientSequence;
    }

    public synchronized void advanceExpectedClientSequence() {
        expectedClientSequence++;
    }

    public synchronized long getAndIncrementServerSequence() {
        return serverSequence++;
    }
}
