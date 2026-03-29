package UI_Bank;

import javax.swing.SwingUtilities;

public class ATMClientMain {
    public static void main(String[] args) {
        String atmId = args.length > 0 ? args[0] : "ATM-1";
        //SwingUtilities.invokeLater(() -> new ATMClientFrame(atmId).setVisible(true));
    }
}
