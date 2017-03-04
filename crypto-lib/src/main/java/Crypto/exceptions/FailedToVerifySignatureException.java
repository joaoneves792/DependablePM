package Crypto.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class FailedToVerifySignatureException extends Exception {
    public FailedToVerifySignatureException(Throwable throwable){
        super("Failed to verify signature", throwable);
    }
}
