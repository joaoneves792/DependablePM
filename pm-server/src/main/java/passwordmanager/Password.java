package passwordmanager;

import Crypto.Cryptography;

/**
 * Created by joao on 3/15/17.
 */
public class Password {

    private final String _domain;
    private final String _username;
    private final String _password;
    private final String _signature;

    public byte[] get_domain() {
        return Cryptography.decodeFromStorage(_domain);
    }

    public byte[] get_username() {
        return Cryptography.decodeFromStorage(_username);
    }

    public byte[] get_password() {
        return Cryptography.decodeFromStorage(_password);
    }

    public byte[] get_signature() {
        return Cryptography.decodeFromStorage(_signature);
    }

    Password(String domain, String username, String password, String signature){
        _domain = domain;
        _username = username;
        _password = password;
        _signature = signature;
    }

    public Boolean checkMatch(String domain, String username){
        System.out.println("+++++++++++++++++++++++++++++++++++++");
        System.out.println(domain);
        System.out.println(_domain);
        System.out.println("+++++++++++++++++++++++++++++++++++++");
        return (domain.equals(_domain) &&  username.equals(_username) );
    }
}
