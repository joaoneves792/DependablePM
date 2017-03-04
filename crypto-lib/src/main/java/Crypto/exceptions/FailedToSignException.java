package Crypto.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class FailedToSignException extends Exception {
    public FailedToSignException(Throwable throwable){
        super("Failed to sign data", throwable);
    }
}
