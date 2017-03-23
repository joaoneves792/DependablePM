package passwordmanager;

import Crypto.Cryptography;

/**
 * Created by joao on 3/15/17.
 */
public class Password {

    private final String _domainUsernameHash;
    private final String _password;
    private final String _signature;

    public byte[] get_domainUsernameHash() {
        return Cryptography.decodeFromStorage(_domainUsernameHash);
    }


    public byte[] get_password() {
        return Cryptography.decodeFromStorage(_password);
    }

    public byte[] get_signature() {
        return Cryptography.decodeFromStorage(_signature);
    }

    Password(String domainUsernameHash, String password, String signature){
        _domainUsernameHash = domainUsernameHash;
        _password = password;
        _signature = signature;
    }

    public Boolean checkMatch(String domainUsernameHash){
        return (domainUsernameHash.equals(_domainUsernameHash));
    }
}
