package passwordmanager.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class AuthenticationFailureException extends Exception {
    public AuthenticationFailureException(String message){
        super(message);
    }
    public AuthenticationFailureException(String message, Throwable throwable){
        super(message, throwable);
    }
}
