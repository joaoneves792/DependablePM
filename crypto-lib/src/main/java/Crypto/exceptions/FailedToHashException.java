package Crypto.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class FailedToHashException extends Exception {
    public FailedToHashException(Throwable throwable){
        super("Failed to hash data", throwable);
    }
}
