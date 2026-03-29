package Server_Client;

import Bank_model.TransactionResult;
import Bank_model.UserRecord;
import CryptoLogic.CryptoUtils;
import CryptoLogic.KvMessage;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Map;
import java.util.Properties;
import javax.crypto.SecretKey;

public class ClientHandler implements Runnable {
    private final Socket socket;
    private final BankServer bankServer;
    private SecretKey atmPreKey;

    public ClientHandler(Socket socket, BankServer bankServer) {
        this.socket = socket;
        this.bankServer = bankServer;
        this.atmPreKey = null;
    }

    @Override
    public void run() {
        try (Socket s = socket;
             BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
             PrintWriter out = new PrintWriter(new OutputStreamWriter(s.getOutputStream()), true)) {

            // Send server public key first --> the ATM use it for secure registration
            out.println("SERVER_HELLO|");

            String atmId = "UNKNOWN-ATM";
            String line;

            // Session is null until authentication finishes successfully
            ClientSession session = null;

            // Main message loop for one ATM client
            while ((line = in.readLine()) != null) {
                String[] parts = line.split("\\|", -1);
                String type = parts[0];

                switch (type) {
                    case "ATM_HELLO" -> {
                        // Store ATM identity for logging and handshake tracking.
                        atmId = parts.length > 1 ? parts[1] : "UNKNOWN-ATM";
                        this.atmPreKey = this.bankServer.getPreKey(atmId);
                        bankServer.log("ATM connected: " + atmId);
                        out.println("ATM_HELLO_OK|" + atmId);
                    }

                    case "REGISTER" ->
                        // Registration uses RSA to protect username/password in transit
                        handleRegister(parts, out, atmId);

                    case "LOGIN_INIT" ->
                        // Start login by issuing salt, iteration count, and server nonce
                        handleLoginInit(parts, out, atmId);

                    case "AUTH1" ->
                        // Complete authentication and derive fresh session keys
                        session = handleAuth1(parts, out, atmId);

                    case "REQUEST" -> {
                        // Secure requests are allowed only after authentication.
                        if (session == null) {
                            out.println("ERROR|Not authenticated.");
                        } else {
                            handleSecureRequest(parts, out, session);
                        }
                    }

                    case "QUIT" -> {
                        bankServer.log("Client disconnected: " + atmId);
                        return;
                    }

                    default -> out.println("ERROR|Unknown command.");
                }
            }
        } catch (Exception e) {
            bankServer.log("Client handler error: " + e.getMessage());
        }
    }

    private void handleRegister(String[] parts, PrintWriter out, String atmId) throws Exception {
        if (parts.length < 2) {
            out.println("REGISTER_RESULT|ERROR|Malformed registration.");
            return;
        }

        // Decrypt registration payload using Sever Pkey
        String decrypted = CryptoUtils.utf8(
                CryptoUtils.aesGcmDecrypt(atmPreKey, CryptoUtils.bytes(parts[1]))
        );

        // Decode username and password 
        Properties p = KvMessage.decode(decrypted);
        String username = p.getProperty("username", "").trim();
        String password = p.getProperty("password", "");

        // Store new user in users.db
        boolean ok = bankServer.getDatabase().register(username, password.toCharArray());

        if (ok) {
            bankServer.log("Registered new user '" + username + "' from " + atmId);
            out.println("REGISTER_RESULT|OK|Account created successfully.");
        } else {
            out.println("REGISTER_RESULT|ERROR|Registration failed. Username may already exist or input is empty.");
        }
    }

    private void handleLoginInit(String[] parts, PrintWriter out, String atmId) {
        if (parts.length < 2) {
            out.println("LOGIN_CHALLENGE|ERROR|Bad request");
            return;
        }

        String username = parts[1].trim();
        UserRecord user = bankServer.getDatabase().getUser(username);

        
        if (user == null) {
            out.println("LOGIN_CHALLENGE|ERROR|Unknown user");
            return;
        }

        // Generate a fresh server nonce for challenge-response authentication
        String nonceS = CryptoUtils.b64(CryptoUtils.randomBytes(16));
        PendingHandshakeStore.put(atmId + ":" + username, nonceS);

        // Send salt, PBKDF2 iterations, and nonce to the ATM.
        out.println("LOGIN_CHALLENGE|OK|" + CryptoUtils.b64(user.getSalt()) + "|" + user.getIterations() + "|" + nonceS);
        bankServer.log("Login challenge issued for user '" + username + "' at " + atmId);
    }

    private ClientSession handleAuth1(String[] parts, PrintWriter out, String atmId) throws Exception {
        if (parts.length < 3) {
            out.println("ERROR|Malformed AUTH1");
            return null;
        }

        String username = parts[1].trim();
        UserRecord user = bankServer.getDatabase().getUser(username);

        if (user == null) {
            out.println("AUTH_RESULT|ERROR|Unknown user");
            return null;
        }

        // Rebuild the password-derived key stored for this user
        SecretKey pskKey = CryptoUtils.aesKeyFromBytes(user.getPsk());

        // Decrypt the client's authentication messages
        String decrypted = CryptoUtils.utf8(CryptoUtils.aesGcmDecrypt(pskKey, CryptoUtils.unb64(parts[2])));
        Properties p = KvMessage.decode(decrypted);

        String nonceS = p.getProperty("nonceS", "");
        String expectedNonceS = PendingHandshakeStore.get(atmId + ":" + username);

        // Verify server nonce to ensure freshness and correct challenge matching
        if (expectedNonceS == null || !expectedNonceS.equals(nonceS)) {
            out.println("AUTH_RESULT|ERROR|Server nonce mismatch");
            return null;
        }

        //We're all good now, the client has verified the server, let's verify the ATM
        String nonceC = p.getProperty("nonceC", "");
        String clientRandomB64 = p.getProperty("clientRandom", "");
        byte[] clientRandom = CryptoUtils.unb64(clientRandomB64);

        // Generate fresh randomness from the server side
        byte[] serverRandom = CryptoUtils.randomBytes(32);

        // Build a fresh master seed from both sides' values
        byte[] masterSeed = CryptoUtils.hmacSha256(
                CryptoUtils.hmacKeyFromBytes(user.getPsk()),
                CryptoUtils.bytes(
                        username + "|" + nonceC + "|" + nonceS + "|" +
                        CryptoUtils.b64(clientRandom) + "|" + CryptoUtils.b64(serverRandom)
                )
        );

        // Derive separate keys for encryption and MAC
        SecretKey encKey = CryptoUtils.hkdfExpand(masterSeed, "BANK-ENC", 16);
        SecretKey macKey = CryptoUtils.hmacKeyFromBytes(
                CryptoUtils.hkdfExpand(masterSeed, "BANK-MAC", 32).getEncoded()
        );

        // Send server proof back to the ATM
        Properties response = new Properties();
        response.setProperty("nonceC", nonceC);
        response.setProperty("nonceS", nonceS);
        response.setProperty("serverRandom", CryptoUtils.b64(serverRandom));
        response.setProperty("message", "Authenticated");

        String responseText = KvMessage.encode(response);
        out.println("AUTH_OK|" + CryptoUtils.b64(CryptoUtils.aesGcmEncrypt(pskKey, CryptoUtils.bytes(responseText))));

        // Authentication finished, so clear pending handshake state
        PendingHandshakeStore.remove(atmId + ":" + username);
        bankServer.log("User '" + username + "' authenticated successfully from " + atmId);

        // Create secure session for future transaction messages
        return new ClientSession(username, atmId, encKey, macKey);
    }

    private void handleSecureRequest(String[] parts, PrintWriter out, ClientSession session) throws Exception {
        if (parts.length < 3) {
            out.println("ERROR|Malformed secure request");
            return;
        }

        byte[] cipher = CryptoUtils.unb64(parts[1]);
        byte[] receivedMac = CryptoUtils.unb64(parts[2]);

        // Verify MAC first before decrypting
        byte[] expectedMac = CryptoUtils.hmacSha256(session.getMacKey(), cipher);
        if (!CryptoUtils.constantTimeEquals(receivedMac, expectedMac)) {
            out.println("ERROR|MAC verification failed");
            bankServer.log("MAC verification failed for user '" + session.getUsername() + "'");
            return;
        }

        // Decrypt the protected request
        String plain = CryptoUtils.utf8(CryptoUtils.aesCbcDecrypt(session.getEncryptionKey(), cipher));
        Properties request = KvMessage.decode(plain);

        // Check sequence number to block replay or out-of-order requests
        long receivedSeq = Long.parseLong(request.getProperty("seq", "0"));
        if (receivedSeq != session.getExpectedClientSequence()) {
            out.println("ERROR|Sequence number mismatch");
            bankServer.log("Replay/out-of-order detected for user '" + session.getUsername() + "'");
            return;
        }
        session.advanceExpectedClientSequence();

        String operation = request.getProperty("op", "");
        TransactionResult result;
        String auditAction;

        // Execute requested banking operation
        switch (operation) {
            case "DEPOSIT" -> {
                double amount = Double.parseDouble(request.getProperty("amount", "0"));
                result = bankServer.getDatabase().deposit(session.getUsername(), amount);
                auditAction = "Deposit " + amount;
            }
            case "WITHDRAW" -> {
                double amount = Double.parseDouble(request.getProperty("amount", "0"));
                result = bankServer.getDatabase().withdraw(session.getUsername(), amount);
                auditAction = "Withdraw " + amount;
            }
            case "BALANCE" -> {
                result = bankServer.getDatabase().balance(session.getUsername());
                auditAction = "Balance Inquiry";
            }
            default -> {
                result = new TransactionResult(false, "Unknown operation.", 0);
                auditAction = "Unknown";
            }
        }

        // Write encryp  audit log entry for valid actions
        if (!"Unknown".equals(auditAction)) {
            bankServer.getAuditLogger().append(session.getUsername(), auditAction, result.getBalance());
            bankServer.log("Audit entry written for user '" + session.getUsername() + "': " + auditAction);
        }

        // Build secure response back to the ATM
        Properties response = new Properties();
        response.setProperty("ok", String.valueOf(result.isSuccess()));
        response.setProperty("message", result.getMessage());
        response.setProperty("balance", String.format("%.2f", result.getBalance()));
        response.setProperty("seq", String.valueOf(session.getAndIncrementServerSequence()));

        String responseText = KvMessage.encode(response);
        byte[] encrypted = CryptoUtils.aesCbcEncrypt(session.getEncryptionKey(), CryptoUtils.bytes(responseText));
        byte[] mac = CryptoUtils.hmacSha256(session.getMacKey(), encrypted);

        out.println("RESPONSE|" + CryptoUtils.b64(encrypted) + "|" + CryptoUtils.b64(mac));
    }

    // Temporary storage for pending login challenges before authentication completes
    private static final class PendingHandshakeStore {
        private static final java.util.concurrent.ConcurrentHashMap<String, String> MAP =
                new java.util.concurrent.ConcurrentHashMap<>();

        private static void put(String key, String value) {
            MAP.put(key, value);
        }

        private static String get(String key) {
            return MAP.get(key);
        }

        private static void remove(String key) {
            MAP.remove(key);
        }
    }
