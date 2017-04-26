package passwordmanager;

import Crypto.Cryptography;

/**
 * Created by joao on 3/15/17.
 */
public class Password {

    private final String _domainUsernameHash;
    private final String _password;
    private final String _signature;
    private final long _timestamp;

    public byte[] get_domainUsernameHash() {
        return Cryptography.decodeFromStorage(_domainUsernameHash);
    }


    public byte[] get_password() {
        return Cryptography.decodeFromStorage(_password);
    }

    public byte[] get_signature() {
        return Cryptography.decodeFromStorage(_signature);
    }

    public long get_timestamp(){return _timestamp;}

    Password(String domainUsernameHash, String password, String signature, long timestamp){
        _domainUsernameHash = domainUsernameHash;
        _password = password;
        _signature = signature;
        _timestamp = timestamp;
    }

    public Boolean checkMatch(String domainUsernameHash){
        return (domainUsernameHash.equals(_domainUsernameHash));
    }
}
