package UI_Bank;

import Server_Client.BankServer;
import java.awt.BorderLayout;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

public class ServerFrame extends JFrame {
    private final JTextArea logArea = new JTextArea();
    private BankServer bankServer;
    private final Map<String, SecretKey> preKeys;
    
    public ServerFrame(Map<String, SecretKey> preKeys) {
        this.preKeys = preKeys;
        super("Bank Server Console");
        setSize(800, 550);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));
        logArea.setEditable(false);
        add(new JScrollPane(logArea), BorderLayout.CENTER);

        JPanel controls = new JPanel();
        JButton startButton = new JButton("Start Server");
        JButton auditButton = new JButton("Show Decrypted Audit Log");
        controls.add(startButton);
        controls.add(auditButton);
        add(controls, BorderLayout.NORTH);

        startButton.addActionListener(e -> {
            try {
                if (bankServer == null) {
                    bankServer = new BankServer(BankServer.DEFAULT_PORT, this, preKeys);
                }
                bankServer.start();
            } catch (Exception ex) {
                appendLog("Failed to start server: " + ex.getMessage());
            }
        });

        auditButton.addActionListener(e -> {
            if (bankServer == null) {
                appendLog("Start the server first.");
            } else {
                appendLog("----- DECRYPTED AUDIT LOG BEGIN -----");
                appendLog(bankServer.getAuditLogPreview());
                appendLog("----- DECRYPTED AUDIT LOG END -----");
            }
        });
    }

    public void appendLog(String text) {
        SwingUtilities.invokeLater(() -> logArea.append(text + System.lineSeparator()));
    }
}
