package Crypto.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class FailedToEncryptException extends Exception {
    public FailedToEncryptException(Throwable throwable){
        super("Failed to encrypt data", throwable);
    }
}
