package passwordmanager.exception;

/**
 * Created by goncalo on 08-03-2017.
 */
public class FailureInitializaCertificatesException extends Exception {
    public FailureInitializaCertificatesException(String message) {
        super(message);
    }

    public FailureInitializaCertificatesException(String message, Throwable cause) {
        super(message, cause);
    }
}
