package passwordmanager;

import java.io.Serializable;

/**
 * Created by joao on 3/4/17.
 */
public class PasswordResponse implements Serializable {
    public final byte[] domain;
    public final byte[] username;
    public final byte[] password;
    public final byte[] signature;

    public final byte[] nonce;

    //TODO: Change the constructor to use the Password class from storage
    public PasswordResponse(byte[] serverResponse){
        domain = new byte[1];
        username = new byte[1];
        password = new byte[1];
        signature = new byte[1];

        nonce = serverResponse;
    }

}