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

    public Password getPassword(byte[] domainUsernameHash){
        String base64DomainUsername = Cryptography.encodeForStorage(domainUsernameHash);
        for (Password pw : _passwordList) {
            if(pw.checkMatch(base64DomainUsername))
                return pw;
        }
        return null;
    }

    public void storePassword(byte[] domainUsernameHash, byte[] password, byte[] signature){
        Password pw = new Password(Cryptography.encodeForStorage(domainUsernameHash), Cryptography.encodeForStorage(password), Cryptography.encodeForStorage(signature));

        Password oldPass = getPassword(domainUsernameHash);
        if(null != oldPass)
            _passwordList.remove(oldPass);
        _passwordList.add(pw);
    }

}
