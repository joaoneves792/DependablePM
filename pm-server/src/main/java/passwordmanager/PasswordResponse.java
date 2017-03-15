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

    public PasswordResponse(Password storedPw, byte[] serverResponse){
        domain = storedPw.get_domain();
        username = storedPw.get_username();
        password = storedPw.get_password();
        signature = storedPw.get_signature();

        nonce = serverResponse;
    }

}