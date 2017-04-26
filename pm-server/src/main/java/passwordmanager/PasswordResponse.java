package passwordmanager;

import java.io.Serializable;

/**
 * Created by joao on 3/4/17.
 */
public class PasswordResponse implements Serializable {
    public final byte[] domainUsernameHash;
    public final byte[] password;
    public final byte[] signature;
    public final long timestamp;

    public final byte[] nonce;

    public PasswordResponse(Password storedPw, byte[] serverResponse){
        domainUsernameHash = storedPw.get_domainUsernameHash();
        password = storedPw.get_password();
        signature = storedPw.get_signature();
        timestamp = storedPw.get_timestamp();

        nonce = serverResponse;
    }

}