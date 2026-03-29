    package Server_Client;

import CryptoLogic.CryptoUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;

public class AuditLogger {
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private final Path keyFile;
    private final Path logFile;
    private final SecretKey auditKey;

    public AuditLogger(Path keyFile, Path logFile) throws Exception {
        this.keyFile = keyFile;
        this.logFile = logFile;
        this.auditKey = loadOrCreateKey();
    }

    private SecretKey loadOrCreateKey() throws Exception {
        if (Files.exists(keyFile)) {
            return CryptoUtils.aesKeyFromBytes(CryptoUtils.unb64(Files.readString(keyFile).trim()));
        }
        SecretKey key = CryptoUtils.generateAESKey(128);
        Files.writeString(keyFile, CryptoUtils.b64(key.getEncoded()), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        return key;
    }

    public synchronized void append(String customerId, String action, double balanceAfter) throws Exception {
        String plain = String.format("CustomerID=%s | Action=%s | Time=%s | BalanceAfter=%.2f",
                customerId,
                action,
                LocalDateTime.now().format(FORMATTER),
                balanceAfter);
        byte[] cipher = CryptoUtils.aesGcmEncrypt(auditKey, CryptoUtils.bytes(plain));
        Files.writeString(logFile, CryptoUtils.b64(cipher) + System.lineSeparator(),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    public synchronized List<String> readDecryptedEntries() throws Exception {
        List<String> entries = new ArrayList<>();
        if (!Files.exists(logFile)) {
            return entries;
        }
        for (String line : Files.readAllLines(logFile)) {
            if (line.isBlank()) {
                continue;
            }
            byte[] plain = CryptoUtils.aesGcmDecrypt(auditKey, CryptoUtils.unb64(line.trim()));
            entries.add(CryptoUtils.utf8(plain));
        }
        return entries;
    }

    public Path getLogFile() {
        return logFile;
    }
}
