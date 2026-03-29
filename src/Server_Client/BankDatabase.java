package Server_Client;

import Bank_model.TransactionResult;
import Bank_model.UserRecord;
import CryptoLogic.CryptoUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class BankDatabase {
    private final Map<String, UserRecord> users = new ConcurrentHashMap<>();
    private final Path storageFile;

    public BankDatabase(Path storageFile) throws IOException {
        this.storageFile = storageFile;
        if (Files.exists(storageFile)) {
            load();
        }
    }

    public synchronized boolean register(String username, char[] password) throws Exception {
        if (username == null || username.isBlank() || password == null || password.length == 0) {
            return false;
        }
        if (users.containsKey(username)) {
            return false;
        }
        byte[] salt = CryptoUtils.randomBytes(16);
        int iterations = 120_000;
        byte[] psk = CryptoUtils.pbkdf2(password, salt, iterations, 32);
        users.put(username, new UserRecord(username, salt, iterations, psk, 0.0));
        save();
        return true;
    }

    public UserRecord getUser(String username) {
        System.out.println("Grabbing user: " + username);
        return users.get(username);
    }

    public synchronized TransactionResult deposit(String username, double amount) throws IOException {
        UserRecord user = users.get(username);
        if (user == null) {
            return new TransactionResult(false, "User not found.", 0);
        }
        if (amount <= 0) {
            return new TransactionResult(false, "Deposit amount must be positive.", user.getBalance());
        }
        double newBalance = user.getBalance() + amount;
        user.setBalance(newBalance);
        save();
        return new TransactionResult(true, String.format("Deposit successful: $%.2f", amount), newBalance);
    }

    public synchronized TransactionResult withdraw(String username, double amount) throws IOException {
        UserRecord user = users.get(username);
        if (user == null) {
            return new TransactionResult(false, "User not found.", 0);
        }
        if (amount <= 0) {
            return new TransactionResult(false, "Withdrawal amount must be positive.", user.getBalance());
        }
        if (user.getBalance() < amount) {
            return new TransactionResult(false, "Insufficient funds.", user.getBalance());
        }
        double newBalance = user.getBalance() - amount;
        user.setBalance(newBalance);
        save();
        return new TransactionResult(true, String.format("Withdrawal successful: $%.2f", amount), newBalance);
    }

    public synchronized TransactionResult balance(String username) {
        UserRecord user = users.get(username);
        if (user == null) {
            return new TransactionResult(false, "User not found.", 0);
        }
        return new TransactionResult(true, String.format("Current balance: $%.2f", user.getBalance()), user.getBalance());
    }

    private void load() throws IOException {
        for (String line : Files.readAllLines(storageFile)) {
            if (line.isBlank()) {
                continue;
            }
            String[] parts = line.split("\\|");
            if (parts.length != 5) {
                continue;
            }
            String username = parts[0];
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            int iterations = Integer.parseInt(parts[2]);
            byte[] psk = Base64.getDecoder().decode(parts[3]);
            double balance = Double.parseDouble(parts[4]);
            users.put(username, new UserRecord(username, salt, iterations, psk, balance));
        }
    }

    private synchronized void save() throws IOException {
        StringBuilder builder = new StringBuilder();
        for (UserRecord user : users.values()) {
            builder.append(user.getUsername()).append('|')
                    .append(Base64.getEncoder().encodeToString(user.getSalt())).append('|')
                    .append(user.getIterations()).append('|')
                    .append(Base64.getEncoder().encodeToString(user.getPsk())).append('|')
                    .append(user.getBalance())
                    .append(System.lineSeparator());
        }
        Files.writeString(storageFile, builder.toString(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }
}
