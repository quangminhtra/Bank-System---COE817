package UI_Bank;

import java.util.HashMap;
import javax.crypto.SecretKey;
import javax.swing.SwingUtilities;
import CryptoLogic.CryptoUtils;

public class DemoLauncher {
    public static void main(String[] args) {
        HashMap<String, SecretKey> preKeys = new HashMap<>();
        try{
        preKeys.put("ATM-1", CryptoUtils.generateAESKey(CryptoUtils.keySize));
        preKeys.put("ATM-2", CryptoUtils.generateAESKey(CryptoUtils.keySize));
        preKeys.put("ATM-3", CryptoUtils.generateAESKey(CryptoUtils.keySize));
        }catch (Exception e){
            e.printStackTrace();
        }
        
        SwingUtilities.invokeLater(() -> {
            new ServerFrame(preKeys).setVisible(true);
            new ATMClientFrame("ATM-1",preKeys.get("ATM-1")).setVisible(true);
            new ATMClientFrame("ATM-2",preKeys.get("ATM-2")).setVisible(true);
            new ATMClientFrame("ATM-3",preKeys.get("ATM-3")).setVisible(true);
        });
    }
}
