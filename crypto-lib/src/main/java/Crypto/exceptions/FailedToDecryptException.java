package Crypto.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class FailedToDecryptException extends Exception {
    public FailedToDecryptException(Throwable throwable){
        super("Failed to decrypt data", throwable);
    }
}
