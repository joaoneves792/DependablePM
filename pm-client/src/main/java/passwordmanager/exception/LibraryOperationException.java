package passwordmanager.exception;

/**
 * Created by goncalo on 08-03-2017.
 */
public class LibraryOperationException extends Exception {
    public LibraryOperationException(String s) {
        super(s);
    }

    public LibraryOperationException(String s, Throwable throwable) {
        super(s, throwable);
    }
}
