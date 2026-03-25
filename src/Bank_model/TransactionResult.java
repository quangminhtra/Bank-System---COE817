package Bank_model;

public class TransactionResult {
    private final boolean success;
    private final String message;
    private final double balance;

    public TransactionResult(boolean success, String message, double balance) {
        this.success = success;
        this.message = message;
        this.balance = balance;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public double getBalance() {
        return balance;
    }
}
