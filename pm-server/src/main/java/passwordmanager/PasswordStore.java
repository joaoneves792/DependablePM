package passwordmanager;

import Crypto.Cryptography;
import passwordmanager.exceptions.PasswordNotFoundException;
import passwordmanager.exceptions.UserAlreadyRegisteredException;
import passwordmanager.exceptions.UserNotRegisteredException;

import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by joao on 3/15/17.
 */
public class PasswordStore {
    private static PasswordStore ourInstance = new PasswordStore();
    private static ConcurrentHashMap<String, UserData> _data;

    public static PasswordStore getInstance() {
        return ourInstance;
    }

    private PasswordStore() {
        _data = new ConcurrentHashMap<>();
    }

    public void register(PublicKey pubKey)throws UserAlreadyRegisteredException{
        UserData userData = _data.get(Cryptography.encodeForStorage(pubKey.getEncoded()));
        if(null != userData){
            throw new UserAlreadyRegisteredException("There is already a user registered with this public key");
        }
        userData = new UserData();
        _data.put(Cryptography.encodeForStorage(pubKey.getEncoded()), userData);

    }

    public Password getPassword(PublicKey pubKey, byte[] domain, byte[] username)throws UserNotRegisteredException, PasswordNotFoundException{
        UserData userData = _data.get(Cryptography.encodeForStorage(pubKey.getEncoded()));
        if(null == userData){
            throw new UserNotRegisteredException("User with this public key is not yet registered");
        }
        Password pw = userData.getPassword(domain, username);
        if(null == pw){
            throw new PasswordNotFoundException("There is no password for this domain+username pair for this user");
        }

        return pw;
    }

    public void storePassword(PublicKey pubKey, byte[] domain, byte[] username, byte[] password, byte[] signature)throws UserNotRegisteredException{
        UserData userData = _data.get(Cryptography.encodeForStorage(pubKey.getEncoded()));
        if(null == userData){
            throw new UserNotRegisteredException("User with this public key is not yet registered");
        }

        userData.storePassword(domain, username, password, signature);
    }


}
