package passwordmanager;

import Crypto.Cryptography;

import java.util.LinkedList;
import java.util.List;

/**
 * Created by joao on 3/15/17.
 */
public class UserData {
    private List<Password> _passwordList;

    UserData(){
        _passwordList = new LinkedList<>();
    }

    public Password getPassword(byte[] domain, byte[] username){
        String base64Domain = Cryptography.encodeForStorage(domain);
        String base64username = Cryptography.encodeForStorage(username);
        for (Password pw : _passwordList) {
            if(pw.checkMatch(base64Domain, base64username))
                return pw;
        }
        return null;
    }

    public void storePassword(byte[] domain, byte[] username, byte[] password, byte[] signature){
        Password pw = new Password(Cryptography.encodeForStorage(domain), Cryptography.encodeForStorage(username), Cryptography.encodeForStorage(password),Cryptography.encodeForStorage(signature));
        _passwordList.add(pw);
    }

}
