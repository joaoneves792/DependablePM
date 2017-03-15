package Crypto;

import Crypto.exceptions.FailedToRetrieveKeyException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;


/**
 * Created by joao on 5/4/16.
 */
public class KeyManager {
    private static final String CACERT = "cacert";
    private static final String MYKEY = "mykey";
    private static final String MYCERT = "mycert";
    private static final String SERVERCERT = "dependablepmserver";

    private static KeyStore _ks;

    private static char[] _password;

    private static ConcurrentHashMap<String, X509Certificate> _certCache = new ConcurrentHashMap<>();

    private static KeyManager instance = null;


    private KeyManager(String keystore){
        _ks = loadKeystore(keystore, _password);
        //initializeCAClient();
        try {
            loadCACertificate();
        }catch (FailedToRetrieveKeyException e){
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }

    private KeyManager(){
        //initializeCAClient();
        try {
            loadCACertificate();
        }catch (FailedToRetrieveKeyException e){
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }

    public static KeyManager getInstance(String keystore){
        return getInstance(keystore, new String(_password));
    }

    public static synchronized KeyManager getInstance(String keystore, String password){
        _password = password.toCharArray();
        if(null == instance)
            if(null != keystore)
                instance = new KeyManager(keystore);
            else
                instance = new KeyManager();
        else if(null == _ks && null != keystore)
            _ks = loadKeystore(keystore, _password);
        return instance;
    }

    public static synchronized void close(){
        for(int i=0; i<_password.length; i++){
            _password[i] = '0';
        }
        _ks = null;
        instance = null;
    }

    private static KeyStore loadKeystore(String name, char[] password){
        FileInputStream fis;
        String filename = name + ".jks";
        try {
            fis = new FileInputStream(filename);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(fis, password);
            return keystore;
        } catch (FileNotFoundException e) {
            System.err.println("Keystore file <" + filename + "> not fount.");
            System.exit(-1);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e){
            System.err.println("Failed to load the Keystore" + e.getMessage());
            System.exit(-1);
        }
        return null;
    }

    public synchronized PrivateKey getPrivateKey(String alias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException{
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(_password);
        if((KeyStore.PrivateKeyEntry) _ks.getEntry(alias, protParam) == null){
            throw new KeyStoreException("Error retrieving key...");
        }
        return ((KeyStore.PrivateKeyEntry)(_ks.getEntry(alias, protParam))).getPrivateKey();
    }

    public synchronized PrivateKey getMyPrivateKey() throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException{
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(_password);
        return ((KeyStore.PrivateKeyEntry)(_ks.getEntry(MYKEY, protParam))).getPrivateKey();
    }

    public X509Certificate getMyCertificate()throws CertificateException, SignatureException, FailedToRetrieveKeyException{
        return getCertificate(MYCERT);
    }

    public X509Certificate getServerCertificate()throws CertificateException, SignatureException, FailedToRetrieveKeyException{
        return getCertificate(SERVERCERT);
    }

    public X509Certificate getCertificate(String entity)throws CertificateException, SignatureException, FailedToRetrieveKeyException{
        if(_certCache.containsKey(entity)){
            X509Certificate cert = _certCache.get(entity);
            cert.checkValidity();
            return cert;
        }

        return forceCertificateRefresh(entity);
    }

    private synchronized X509Certificate forceCertificateRefresh(String entity)throws CertificateException, SignatureException, FailedToRetrieveKeyException{

        X509Certificate X509Cert;
        try{
            java.security.cert.Certificate cert = _ks.getCertificate(entity);
            if(null == cert)
                throw new FailedToRetrieveKeyException("Don't have a certificate for this entity");
            X509Cert = (X509Certificate)cert;
        }catch (KeyStoreException e){
            throw new FailedToRetrieveKeyException("KeyStore failed");
        }


        verifyCertificate(X509Cert);

        _certCache.put(entity, X509Cert);
        return X509Cert;
    }

    public X509Certificate getCACertificate(){
        return _certCache.get(CACERT);
    }

    private static synchronized void loadCACertificate()throws FailedToRetrieveKeyException{
        X509Certificate X509Cert;
        try{
            java.security.cert.Certificate cert = _ks.getCertificate(CACERT);
            if(null == cert)
                throw new FailedToRetrieveKeyException("Don't have a certificate for the CA");
            X509Cert = (X509Certificate)cert;
            X509Cert.checkValidity();

            _certCache.put(CACERT, X509Cert);
        }catch (KeyStoreException |
                CertificateNotYetValidException |
                CertificateExpiredException e){
            throw new FailedToRetrieveKeyException("Failed to load the CA certificate");
        }

    }

    private void verifyCertificate(X509Certificate cert)throws CertificateException, SignatureException{
        cert.checkValidity();
        try {
            cert.verify(getCACertificate().getPublicKey());
        }catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e){
            System.err.println("FATAL: Can't verify the signature on a certificate: " + e.getMessage());
            System.exit(-1);
        }
    }
}

