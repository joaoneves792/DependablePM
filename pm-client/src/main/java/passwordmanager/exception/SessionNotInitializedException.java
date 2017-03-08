package passwordmanager.exception;

/**
 * Created by goncalo on 07-03-2017.
 */
public class SessionNotInitializedException extends RuntimeException {
    public SessionNotInitializedException(String msg){
        super(msg);
    }
}
