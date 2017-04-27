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
    private final String _uuid;

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

    public String get_uuid(){return _uuid;}

    Password(String domainUsernameHash, String password, String signature, long timestamp, String uuid){
        _domainUsernameHash = domainUsernameHash;
        _password = password;
        _signature = signature;
        _timestamp = timestamp;
        _uuid = uuid;
    }

    public Boolean checkMatch(String domainUsernameHash){
        return (domainUsernameHash.equals(_domainUsernameHash));
    }
}
