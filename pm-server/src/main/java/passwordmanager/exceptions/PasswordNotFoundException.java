package passwordmanager.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class PasswordNotFoundException extends Exception {
    public PasswordNotFoundException(String message){
        super(message);
    }
    public PasswordNotFoundException(String message, Throwable throwable){
        super(message, throwable);
    }
}
