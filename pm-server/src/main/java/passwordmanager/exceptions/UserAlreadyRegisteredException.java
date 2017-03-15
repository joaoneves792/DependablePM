package passwordmanager.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class UserAlreadyRegisteredException extends Exception {
    public UserAlreadyRegisteredException(String message){
        super(message);
    }
    public UserAlreadyRegisteredException(String message, Throwable throwable){
        super(message, throwable);
    }
}
