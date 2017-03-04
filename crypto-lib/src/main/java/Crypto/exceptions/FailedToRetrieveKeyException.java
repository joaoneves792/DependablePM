package Crypto.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class FailedToRetrieveKeyException extends Exception {
    public FailedToRetrieveKeyException(String message, Throwable throwable){
        super(message, throwable);
    }
    public FailedToRetrieveKeyException(String message){
        super(message);
    }
}
