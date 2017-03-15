package passwordmanager;

import Crypto.Cryptography;
import Crypto.KeyManager;
import passwordmanager.exceptions.UserAlreadyRegisteredException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

/**
 * Created by joao on 3/5/17.
 */
public class ServerConnectionTest {
    private static final char[] PASSWORD = "123456".toCharArray();
    private static final String CACERT = "cacert";
    private static final String MYKEY = "mykey";
    private static final String MYCERT = "mycert";
    private static final String SERVERCERT = "dependablepmserver";

    private static final String PASSWORD_TO_STORE = "strongpassword12345";
    private static final String DOMAIN = "fenix.tecnico.ulisboa.pt";
    private static final String USERNAME = "ist170666";

    private static final String CLIENT_KEYSTORE = "Client1";
    private static final String SERVER_KEYSTORE = "DependablePMServer";


    private static final int NONCE_SIZE = 4;

    X509Certificate clientCert;
    X509Certificate serverCert;
    PrivateKey clientKey;

    ServerConnection sc;

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


    @org.junit.Before
    public void setUp() throws Exception {
        KeyStore ks = loadKeystore(CLIENT_KEYSTORE, PASSWORD);
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(PASSWORD);
        clientKey = ((KeyStore.PrivateKeyEntry)(ks.getEntry(MYKEY, protParam))).getPrivateKey();
        clientCert = (X509Certificate)ks.getCertificate(MYCERT);
        serverCert = (X509Certificate)ks.getCertificate(SERVERCERT);

        /*HACK get the keystore loaded with the password (bypassing the arguments*/
        KeyManager.getInstance(SERVER_KEYSTORE, new String(PASSWORD));

        sc = new ServerConnection();
        try {
            sc.register(clientCert);
        }catch (UserAlreadyRegisteredException e){
            //Ignore it if the user is already registered
        }
    }

    @org.junit.Test
    public void handshake() throws Exception {
        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);
    }

    @org.junit.Test
    public void getServerNonce() throws Exception {
        int n = sc.getServerNonce();
    }

    @org.junit.Test
    public void put() throws Exception {
        byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(sc.getServerNonce()+1).array(), clientKey);
        byte[] username = Cryptography.hash(USERNAME.getBytes());
        byte[] domain = Cryptography.hash(DOMAIN.getBytes());
        byte[] password = Cryptography.asymmetricCipher(PASSWORD_TO_STORE.getBytes(), clientCert.getPublicKey());

        byte[] userdata = new byte[domain.length+username.length+password.length];
        System.arraycopy(domain, 0, userdata, 0, domain.length);
        System.arraycopy(username, 0, userdata, domain.length, username.length);
        System.arraycopy(password, 0, userdata, domain.length+username.length, password.length);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        sc.put(nonce,domain,username,password,clientCert, signature);

    }

    @org.junit.Test
    public void get() throws Exception {

        put();

        int nonce = sc.getServerNonce()+1;
        byte[] username = Cryptography.hash(USERNAME.getBytes());
        byte[] domain = Cryptography.hash(DOMAIN.getBytes());

        byte[] nonceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nonce).array();

        byte[] userdata = new byte[domain.length+username.length+NONCE_SIZE];
        System.arraycopy(domain, 0, userdata, 0, domain.length);
        System.arraycopy(username, 0, userdata, domain.length, username.length);
        System.arraycopy(nonceBytes, 0, userdata, domain.length+username.length, NONCE_SIZE);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        sc.get(nonce, clientCert, domain, username, signature);
    }

}