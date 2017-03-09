package Crypto.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class FailedToGenerateKeyException extends Exception {
    public FailedToGenerateKeyException(String message, Throwable throwable){
        super(message, throwable);
    }
    public FailedToGenerateKeyException(String message){
        super(message);
    }
}
