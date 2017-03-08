package passwordmanager;

import Crypto.exceptions.FailedToRetrieveKeyException;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * Created by goncalo on 07-03-2017.
 */
public class ConnectionState {
    private static final String SERVER_CERT = "dependablepmserver";
    private KeyStore keyStore;
    private String pubKeyAlias;
    private String privKeyAlias;
    private String password;
    private X509Certificate clientCertificate;
    private X509Certificate serverCertificate;

    public ConnectionState(KeyStore keystore){
        this.keyStore = keystore;
    }

    /**
     * Initializes client certificate with the given alias and also initializes the server certificate
     * @param certAlias given String alias from the client certificate
     */
    public void initializeCertificates(String certAlias, String serverAlias) throws FailedToRetrieveKeyException{
        try{
            // Initialize Client certificate
            clientCertificate = (X509Certificate) keyStore.getCertificate(certAlias);

            // Initialize Server certificate
            serverCertificate = (X509Certificate) keyStore.getCertificate(serverAlias);

        }catch (KeyStoreException e){
            throw new FailedToRetrieveKeyException("Failed to load the CA certificate");
        }
    }

    public X509Certificate getClientCertificate() {
        return clientCertificate;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
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
}
