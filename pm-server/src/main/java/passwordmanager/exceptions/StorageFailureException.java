package passwordmanager.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class StorageFailureException extends Exception {
    public StorageFailureException(String message){
        super(message);
    }
    public StorageFailureException(String message, Throwable throwable){
        super(message, throwable);
    }
}
