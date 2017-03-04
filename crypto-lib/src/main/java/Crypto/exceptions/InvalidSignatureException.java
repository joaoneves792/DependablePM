package Crypto.exceptions;

/**
 * Created by joao on 3/4/17.
 */
public class InvalidSignatureException extends Exception {
    public InvalidSignatureException(){
        super("Data is not a valid signature");
    }
}
