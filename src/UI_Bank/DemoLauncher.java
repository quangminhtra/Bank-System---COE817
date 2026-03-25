package UI_Bank;

import javax.swing.SwingUtilities;

public class DemoLauncher {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new ServerFrame().setVisible(true);
            new ATMClientFrame("ATM-1").setVisible(true);
            new ATMClientFrame("ATM-2").setVisible(true);
            new ATMClientFrame("ATM-3").setVisible(true);
        });
    }
}
