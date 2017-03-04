package passwordmanager.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class HandshakeFailedException extends Exception {
    public HandshakeFailedException(String message){
        super(message);
    }
    public HandshakeFailedException(String message, Throwable throwable){
        super(message, throwable);
    }
}
