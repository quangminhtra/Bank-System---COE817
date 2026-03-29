package UI_Bank;

import CryptoLogic.CryptoUtils;
import CryptoLogic.KvMessage;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Properties;
import javax.crypto.SecretKey;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

public class ATMClientFrame extends JFrame {
    private final String atmId;
    private final JTextField hostField = new JTextField("127.0.0.1");
    private final JTextField portField = new JTextField("5050");
    private final JTextField usernameField = new JTextField();
    private final JPasswordField passwordField = new JPasswordField();
    private final JTextField amountField = new JTextField();
    private final JTextArea outputArea = new JTextArea();
    

    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    private final SecretKey preshared;
    private SecretKey encryptionKey;
    private SecretKey macKey;
    private long clientSeq = 1;
    private String loggedInUser;

    public ATMClientFrame(String atmId, SecretKey preshared) {
        super("ATM Client - " + atmId);
        this.atmId = atmId;
        this.preshared = preshared;
        buildUi();
    }

    private void buildUi() {
        setSize(650, 500);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        JPanel top = new JPanel(new GridLayout(0, 2, 6, 6));
        top.add(new JLabel("Server Host"));
        top.add(hostField);
        top.add(new JLabel("Server Port"));
        top.add(portField);
        top.add(new JLabel("Username"));
        top.add(usernameField);
        top.add(new JLabel("Password"));
        top.add(passwordField);
        top.add(new JLabel("Amount"));
        top.add(amountField);
        add(top, BorderLayout.NORTH);

        JPanel buttons = new JPanel(new GridLayout(2, 3, 6, 6));
        JButton connectButton = new JButton("Connect");
        JButton registerButton = new JButton("Register");
        JButton loginButton = new JButton("Login");
        JButton depositButton = new JButton("Deposit");
        JButton withdrawButton = new JButton("Withdraw");
        JButton balanceButton = new JButton("Balance");

        connectButton.addActionListener(e -> safeRun(this::connect));
        registerButton.addActionListener(e -> safeRun(this::register));
        loginButton.addActionListener(e -> safeRun(this::login));
        depositButton.addActionListener(e -> safeRun(() -> sendOperation("DEPOSIT")));
        withdrawButton.addActionListener(e -> safeRun(() -> sendOperation("WITHDRAW")));
        balanceButton.addActionListener(e -> safeRun(() -> sendOperation("BALANCE")));

        buttons.add(connectButton);
        buttons.add(registerButton);
        buttons.add(loginButton);
        buttons.add(depositButton);
        buttons.add(withdrawButton);
        buttons.add(balanceButton);
        add(buttons, BorderLayout.CENTER);

        outputArea.setEditable(false);
        add(new JScrollPane(outputArea), BorderLayout.SOUTH);
        outputArea.setRows(15);
        log("Got shared key: " + CryptoUtils.b64(this.preshared.getEncoded()));
    }

    private void safeRun(Action action) {
        try {
            action.run();
        } catch (Exception ex) {
            log("ERROR: " + ex.getMessage());
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void connect() throws Exception {
        if (socket != null && socket.isConnected() && !socket.isClosed()) {
            log("Already connected.");
            return;
        }
        socket = new Socket(hostField.getText().trim(), Integer.parseInt(portField.getText().trim()));
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

        String hello = in.readLine();
        String[] parts = hello.split("\\|", -1);
        if (!"SERVER_HELLO".equals(parts[0])) {
            throw new IllegalStateException("Unexpected server response: " + hello);
        }
        out.println("ATM_HELLO|" + atmId);
        log("Connected to bank server.");
        log("Server public key received for secure registration.");
        log("Server says: " + in.readLine());
    }

    private void register() throws Exception {
        ensureConnected();
        Properties p = new Properties();
        p.setProperty("username", usernameField.getText().trim());
        p.setProperty("password", new String(passwordField.getPassword()));
        byte[] cipher = CryptoUtils.aesGcmEncrypt(preshared, CryptoUtils.bytes(KvMessage.encode(p)));
        out.println("REGISTER|" + CryptoUtils.b64(cipher));
        log("Sent register cipher: " + CryptoUtils.b64(cipher));
        String response = in.readLine();
        log("Register response: " + response);
    }

    private void login() throws Exception {
        ensureConnected();
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        out.println("LOGIN_INIT|" + username);
        log("Loggin in as: " + username);
        String challenge = in.readLine();
        String[] parts = challenge.split("\\|", -1);
        if (!"LOGIN_CHALLENGE".equals(parts[0]) || !"OK".equals(parts[1])) {
            log("Login failed before authentication: " + challenge);
            return;
        }
        
        String loginChallengeOk = CryptoUtils.utf8(CryptoUtils.aesGcmDecrypt(preshared, CryptoUtils.unb64(parts[2])));
        String[] loginOkParts = loginChallengeOk.split("\\|", -1);
        byte[] salt = CryptoUtils.unb64(loginOkParts[0]);
        int iterations = Integer.parseInt(loginOkParts[1]);
        String nonceS = loginOkParts[2];

        String nonceC = CryptoUtils.b64(CryptoUtils.randomBytes(16));
        byte[] clientRandom = CryptoUtils.randomBytes(32);
        Properties auth1 = new Properties();

        //build client's auth message, include the server's nonce
        auth1.setProperty("nonceS", nonceS);
        auth1.setProperty("nonceC", nonceC);
        auth1.setProperty("clientRandom", CryptoUtils.b64(clientRandom));
        auth1.setProperty("username", username);
        auth1.setProperty("pswd", CryptoUtils.b64(CryptoUtils.pbkdf2(password.toCharArray(), salt, iterations, 32)));
        log("Going to send psk: " + auth1.get("pswd"));
        byte[] authCipher = CryptoUtils.aesGcmEncrypt(preshared, CryptoUtils.bytes(KvMessage.encode(auth1)));
        out.println("AUTH1|" + CryptoUtils.b64(authCipher));
        //check if the server verified the customer
        String authOk = in.readLine();
        String[] authParts = authOk.split("\\|", -1);
        if (!"AUTH_OK".equals(authParts[0])) {
            log("Authentication failed: " + authOk);
            return;
        }

        //now atm must verify the server
        String decrypted = CryptoUtils.utf8(CryptoUtils.aesGcmDecrypt(preshared, CryptoUtils.unb64(authParts[1])));
        Properties auth2 = KvMessage.decode(decrypted);
        //double check server nonce
        if (!(nonceC.equals(auth2.getProperty("nonceC")) && nonceS.equals(auth2.getProperty("nonceS")))) {
            throw new IllegalStateException("Server authentication failed. NonceC mismatch.");
        }
        byte[] serverRandom = CryptoUtils.unb64(auth2.getProperty("serverRandom"));
        byte[] masterSeed = CryptoUtils.hmacSha256(CryptoUtils.hmacKeyFromBytes(preshared.getEncoded()),
                CryptoUtils.bytes(username + "|" + nonceC + "|" + nonceS + "|" + CryptoUtils.b64(clientRandom) + "|" + CryptoUtils.b64(serverRandom)));
        encryptionKey = CryptoUtils.hkdfExpand(masterSeed, "BANK-ENC", 16);
        macKey = CryptoUtils.hmacKeyFromBytes(CryptoUtils.hkdfExpand(masterSeed, "BANK-MAC", 32).getEncoded());
        clientSeq = 1;
        loggedInUser = username;
        log("Login success for user '" + username + "'.");
        log("Fresh Master Secret established. Derived Encryption key and MAC key are ready.");
    }

    private void sendOperation(String operation) throws Exception {
        ensureAuthenticated();
        Properties request = new Properties();
        request.setProperty("op", operation);
        request.setProperty("seq", String.valueOf(clientSeq++));
        if (!"BALANCE".equals(operation)) {
            request.setProperty("amount", amountField.getText().trim());
        }
        byte[] cipher = CryptoUtils.aesCbcEncrypt(encryptionKey, CryptoUtils.bytes(KvMessage.encode(request)));
        byte[] mac = CryptoUtils.hmacSha256(macKey, cipher);
        out.println("REQUEST|" + CryptoUtils.b64(cipher) + "|" + CryptoUtils.b64(mac));

        String line = in.readLine();
        if (line == null) {
            throw new IllegalStateException("Server closed the connection.");
        }
        if (line.startsWith("ERROR|")) {
            log("Server error: " + line);
            return;
        }
        String[] parts = line.split("\\|", -1);
        byte[] respCipher = CryptoUtils.unb64(parts[1]);
        byte[] respMac = CryptoUtils.unb64(parts[2]);
        byte[] expectedMac = CryptoUtils.hmacSha256(macKey, respCipher);
        if (!CryptoUtils.constantTimeEquals(respMac, expectedMac)) {
            throw new IllegalStateException("Response MAC check failed.");
        }
        String plain = CryptoUtils.utf8(CryptoUtils.aesCbcDecrypt(encryptionKey, respCipher));
        Properties response = KvMessage.decode(plain);
        log("Transaction result for " + loggedInUser + ": " + response.getProperty("message")
                + " | Balance = $" + response.getProperty("balance"));
    }

    private void ensureConnected() {
        if (socket == null || socket.isClosed()) {
            throw new IllegalStateException("Connect to the server first.");
        }
    }

    private void ensureAuthenticated() {
        ensureConnected();
        if (encryptionKey == null || macKey == null) {
            throw new IllegalStateException("Login first to derive session keys.");
        }
    }

    private void log(String text) {
        SwingUtilities.invokeLater(() -> outputArea.append(text + System.lineSeparator()));
    }

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }
}
