package passwordmanager;

import Crypto.KeyManager;
import Crypto.exceptions.FailedToRetrieveKeyException;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * Created by goncalo on 07-03-2017.
 */
public class ConnectionState {
    private static final String SERVER_CERT = "dependablepmserver";
    //private KeyStore keyStore;
    private String pubKeyAlias;
    private String privKeyAlias;
    private String password;
    private X509Certificate clientCertificate;
    private X509Certificate serverCertificate;
    private KeyManager keyManager;

    public ConnectionState(String keyStoreName, String password){
        keyManager = KeyManager.getInstance(keyStoreName, password);
    }

    /**
     * Initializes client certificate with the given alias and also initializes the server certificate
     * @param certAlias given String alias from the client certificate
     */
    public void initializeCertificates(String certAlias, String serverAlias) throws FailedToRetrieveKeyException{
        try{
            // Initialize Client certificate
            clientCertificate = keyManager.getCertificate(certAlias);

            // Initialize Server certificate
            serverCertificate = keyManager.getCertificate(serverAlias);

        }catch(SignatureException e){
            throw new FailedToRetrieveKeyException("Failed to load the CA certificate", e);
        }catch(CertificateException e){
            throw new FailedToRetrieveKeyException("Failed to load the CA certificate", e);
        }
    }

    public X509Certificate getClientCertificate() {
        return clientCertificate;
    }

    public void setPubKeyAlias(String pubKeyAlias) {
        this.pubKeyAlias = pubKeyAlias;
    }

    public void setPrivKeyAlias(String privKeyAlias) {
        this.privKeyAlias = privKeyAlias;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPubKeyAlias() {
        return pubKeyAlias;
    }

    public String getPrivKeyAlias() {
        return privKeyAlias;
    }

    public String getPassword() {
        return password;
    }

    public X509Certificate getServerCertificate() {
        return serverCertificate;
    }

    public KeyManager getKeyManager() {
        return keyManager;
    }
}
