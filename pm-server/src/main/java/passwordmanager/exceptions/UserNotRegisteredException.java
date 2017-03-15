package passwordmanager.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class UserNotRegisteredException extends Exception {
    public UserNotRegisteredException(String message){
        super(message);
    }
    public UserNotRegisteredException(String message, Throwable throwable){
        super(message, throwable);
    }
}
