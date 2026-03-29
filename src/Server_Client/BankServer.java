package Server_Client;

import CryptoLogic.CryptoUtils;
import UI_Bank.ServerFrame;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;

public class BankServer {
    public static final int DEFAULT_PORT = 5050;
    private final int port;
    private final Map<String, SecretKey> preKeys;
    private final KeyPair rsaKeyPair;
    private final BankDatabase database;
    private final AuditLogger auditLogger;
    private final ExecutorService clientPool = Executors.newCachedThreadPool();
    private final ServerFrame serverFrame;
    private volatile boolean running;

    public BankServer(int port, ServerFrame serverFrame, Map<String, SecretKey> preKeys) throws Exception {
        this.port = port;
        this.serverFrame = serverFrame;
        this.rsaKeyPair = CryptoUtils.generateRSAKeyPair();
        this.database = new BankDatabase(Path.of("users.db"));
        this.auditLogger = new AuditLogger(Path.of("audit.key"), Path.of("audit.log.enc"));
        this.preKeys = preKeys;
    }

    public SecretKey getPreKey(String atmId){
        return preKeys.get(atmId);
    }
    
    public void start() {
        if (running) {
            log("Server already running.");
            return;
        }
        running = true;
        Thread acceptThread = new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                log("Bank server listening on port " + port);
                log("Server public key distributed to ATM clients at connection time.");
                while (running) {
                    Socket socket = serverSocket.accept();
                    log("Connection received from " + socket.getRemoteSocketAddress());
                    clientPool.submit(new ClientHandler(socket, this));
                }
            } catch (IOException e) {
                if (running) {
                    log("Server stopped unexpectedly: " + e.getMessage());
                }
            }
        }, "bank-accept-thread");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    public void log(String message) {
        System.out.println(message);
        if (serverFrame != null) {
            serverFrame.appendLog(message);
        }
    }

    public KeyPair getRsaKeyPair() {
        return rsaKeyPair;
    }

    public BankDatabase getDatabase() {
        return database;
    }

    public AuditLogger getAuditLogger() {
        return auditLogger;
    }

    public String getAuditLogPreview() {
        try {
            return String.join(System.lineSeparator(), auditLogger.readDecryptedEntries());
        } catch (Exception e) {
            return "Failed to read audit log: " + e.getMessage();
        }
    }
}
