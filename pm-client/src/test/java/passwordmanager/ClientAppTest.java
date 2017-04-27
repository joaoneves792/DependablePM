package passwordmanager;

import Crypto.Cryptography;
import launcher.ProcessManagerInterface;
import passwordmanager.exceptions.AuthenticationFailureException;
import passwordmanager.exceptions.HandshakeFailedException;
import passwordmanager.exceptions.UserAlreadyRegisteredException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.rmi.Naming;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;

import static org.junit.Assert.*;

/**
 * Created by joao on 3/5/17.
 */
public class ClientAppTest {
    private static final char[] PASSWORD = "123456".toCharArray();
    private static final String MYKEY = "mykey";
    private static final String MYCERT = "mycert";
    private static final String SERVERCERT = "dependablepmserver";

    private static final String PASSWORD_TO_STORE = "strongpassword12345";
    private static final String PASSWORD_TO_OVERWRITE = "weakpassword54321";
    private static final String DOMAIN = "fenix.tecnico.ulisboa.pt";
    private static final String USERNAME = "ist170666";

    private static final String CLIENT_KEYSTORE = "Client1";

    private static final int NONCE_SIZE = 4;

    private static final int PROCESS_MANAGER_PORT = 2000;
    private static final String PROCESS_MANAGER_NAME = "ProcessManager";

    private X509Certificate clientCert;
    private X509Certificate serverCert;
    private PrivateKey clientKey;

    private long _timestamp = 0;

    private static boolean _reset = false;

    private ServerConnectionInterface sc;

    @org.junit.Before
    public void setUp() throws Exception {
        if(!_reset) {
            ProcessManagerInterface processManager = (ProcessManagerInterface) Naming.lookup("rmi://" + "localhost" + ":" + PROCESS_MANAGER_PORT + "/" + PROCESS_MANAGER_NAME);
            processManager.killAll();
            processManager.launchAll();
            _reset = true;
        }
        PMService pm = (PMService) Naming.lookup("rmi://" + "localhost" +":"+2021+"/PMService");

        KeyStore ks = loadKeystore(CLIENT_KEYSTORE, PASSWORD);
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(PASSWORD);
        clientKey = ((KeyStore.PrivateKeyEntry)(ks.getEntry(MYKEY, protParam))).getPrivateKey();
        clientCert = (X509Certificate)ks.getCertificate(MYCERT);
        serverCert = (X509Certificate)ks.getCertificate(SERVERCERT);
        sc = pm.connect();

        try{
            sc.register(clientCert);
        }catch (UserAlreadyRegisteredException e){
            //Ignore we only want to actually register the first time it runs
        }
    }


    public static byte flipBits(byte data){
        return (byte)(data ^ 0xFF);
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

    /*-------------------------------------------------------------------------------------
    START OF POSITIVE TESTING
    -------------------------------------------------------------------------------------*/

    @org.junit.Test
    public void handshake() throws Exception {
        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);
    }

    @org.junit.Test
    public void getServerNonce() throws Exception {
        sc.getServerNonce();
    }

    @org.junit.Test
    public void put() throws Exception {
        byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(sc.getServerNonce()+1).array(), clientKey);
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());
        byte[] password = Cryptography.asymmetricCipher(PASSWORD_TO_STORE.getBytes(), clientCert.getPublicKey());

        UUID uuid = UUID.randomUUID();
        byte[] ts = ByteBuffer.allocate(Long.SIZE).putLong(++_timestamp).array();
        byte[] id = uuid.toString().getBytes();
        byte[] userdata = new byte[domainUsernameHash.length+password.length+ts.length+id.length];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(password, 0, userdata, domainUsernameHash.length, password.length);
        System.arraycopy(ts, 0, userdata, domainUsernameHash.length+password.length, ts.length);
        System.arraycopy(id, 0, userdata, domainUsernameHash.length+password.length+ts.length, id.length);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        sc.put(nonce,domainUsernameHash,password,clientCert, signature, _timestamp, uuid.toString());
    }

    @org.junit.Test
    public void get() throws Exception {
        put();

        int nonce = sc.getServerNonce()+1;
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());

        byte[] nonceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nonce).array();

        byte[] userdata = new byte[domainUsernameHash.length+NONCE_SIZE];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(nonceBytes, 0, userdata, domainUsernameHash.length, NONCE_SIZE);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        PasswordResponse pw = sc.get(nonce, clientCert, domainUsernameHash, signature);
        assertEquals(PASSWORD_TO_STORE , new String(Cryptography.asymmetricDecipher(pw.password, clientKey)));
    }

    @org.junit.Test
    public void putOverwrite() throws Exception {
        put();

        byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(sc.getServerNonce()+1).array(), clientKey);
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());
        byte[] password = Cryptography.asymmetricCipher(PASSWORD_TO_OVERWRITE.getBytes(), clientCert.getPublicKey());

        UUID uuid = UUID.randomUUID();
        byte[] ts = ByteBuffer.allocate(Long.SIZE).putLong(++_timestamp).array();
        byte[] id = uuid.toString().getBytes();
        byte[] userdata = new byte[domainUsernameHash.length+password.length+ts.length+id.length];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(password, 0, userdata, domainUsernameHash.length, password.length);
        System.arraycopy(ts, 0, userdata, domainUsernameHash.length+password.length, ts.length);
        System.arraycopy(id, 0, userdata, domainUsernameHash.length+password.length+ts.length, id.length);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        sc.put(nonce,domainUsernameHash,password,clientCert, signature, _timestamp, uuid.toString());

        int nonce2 = sc.getServerNonce()+1;

        byte[] nonceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nonce2).array();

        userdata = new byte[domainUsernameHash.length+NONCE_SIZE];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(nonceBytes, 0, userdata, domainUsernameHash.length, NONCE_SIZE);

        signature = Cryptography.sign(userdata, clientKey);


        myNounce = new SecureRandom().nextInt();
        response = sc.handshake(myNounce);

        decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        PasswordResponse pw = sc.get(nonce2, clientCert, domainUsernameHash, signature);
        assertEquals(PASSWORD_TO_OVERWRITE , new String(Cryptography.asymmetricDecipher(pw.password, clientKey)));
    }
    /*-------------------------------------------------------------------------------------
    START OF NEGATIVE TESTING
    -------------------------------------------------------------------------------------*/

    @org.junit.Test(expected = HandshakeFailedException.class)
    public void putNoHandhake()throws Exception{
        byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(sc.getServerNonce()+1).array(), clientKey);
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());
        byte[] password = Cryptography.asymmetricCipher(PASSWORD_TO_STORE.getBytes(), clientCert.getPublicKey());

        UUID uuid = UUID.randomUUID();
        byte[] ts = ByteBuffer.allocate(Long.SIZE).putLong(++_timestamp).array();
        byte[] id = uuid.toString().getBytes();
        byte[] userdata = new byte[domainUsernameHash.length+password.length+ts.length+id.length];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(password, 0, userdata, domainUsernameHash.length, password.length);
        System.arraycopy(ts, 0, userdata, domainUsernameHash.length+password.length, ts.length);
        System.arraycopy(id, 0, userdata, domainUsernameHash.length+password.length+ts.length, id.length);
        byte[] signature = Cryptography.sign(userdata, clientKey);


        sc.put(nonce,domainUsernameHash,password,clientCert, signature, _timestamp, uuid.toString());
    }

    @org.junit.Test(expected = HandshakeFailedException.class)
    public void getNoHandhake()throws Exception{
        int nonce = sc.getServerNonce()+1;
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());

        byte[] nonceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nonce).array();

        byte[] userdata = new byte[domainUsernameHash.length+NONCE_SIZE];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(nonceBytes, 0, userdata, domainUsernameHash.length, NONCE_SIZE);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        PasswordResponse pw = sc.get(nonce, clientCert, domainUsernameHash, signature);
    }

    @org.junit.Test(expected = AuthenticationFailureException.class)
    public void putBadNonce()throws Exception{
        byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(sc.getServerNonce()+2).array(), clientKey);
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());
        byte[] password = Cryptography.asymmetricCipher(PASSWORD_TO_STORE.getBytes(), clientCert.getPublicKey());

        UUID uuid = UUID.randomUUID();
        byte[] ts = ByteBuffer.allocate(Long.SIZE).putLong(++_timestamp).array();
        byte[] id = uuid.toString().getBytes();
        byte[] userdata = new byte[domainUsernameHash.length+password.length+ts.length+id.length];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(password, 0, userdata, domainUsernameHash.length, password.length);
        System.arraycopy(ts, 0, userdata, domainUsernameHash.length+password.length, ts.length);
        System.arraycopy(id, 0, userdata, domainUsernameHash.length+password.length+ts.length, id.length);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        sc.put(nonce,domainUsernameHash,password,clientCert, signature, _timestamp, uuid.toString());

    }

    @org.junit.Test(expected = AuthenticationFailureException.class)
    public void getBadNonce()throws Exception{
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());

        int nonce = sc.getServerNonce()+2;
        byte[] nonceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nonce).array();

        byte[] userdata = new byte[domainUsernameHash.length+NONCE_SIZE];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(nonceBytes, 0, userdata, domainUsernameHash.length, NONCE_SIZE);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        sc.get(nonce, clientCert, domainUsernameHash, signature);

    }

    @org.junit.Test(expected = AuthenticationFailureException.class)
    public void putBadNonceCipher()throws Exception{
        byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(sc.getServerNonce()+1).array(), clientKey);
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());
        byte[] password = Cryptography.asymmetricCipher(PASSWORD_TO_STORE.getBytes(), clientCert.getPublicKey());

        UUID uuid = UUID.randomUUID();
        byte[] ts = ByteBuffer.allocate(Long.SIZE).putLong(++_timestamp).array();
        byte[] id = uuid.toString().getBytes();
        byte[] userdata = new byte[domainUsernameHash.length+password.length+ts.length+id.length];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(password, 0, userdata, domainUsernameHash.length, password.length);
        System.arraycopy(ts, 0, userdata, domainUsernameHash.length+password.length, ts.length);
        System.arraycopy(id, 0, userdata, domainUsernameHash.length+password.length+ts.length, id.length);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        nonce[0] = flipBits(nonce[0]);
        sc.put(nonce,domainUsernameHash,password,clientCert, signature, _timestamp, uuid.toString());

    }
    @org.junit.Test(expected = AuthenticationFailureException.class)
    public void putTamperedMessageUsername()throws Exception{
        byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(sc.getServerNonce()+1).array(), clientKey);
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());
        byte[] password = Cryptography.asymmetricCipher(PASSWORD_TO_STORE.getBytes(), clientCert.getPublicKey());

        UUID uuid = UUID.randomUUID();
        byte[] ts = ByteBuffer.allocate(Long.SIZE).putLong(++_timestamp).array();
        byte[] id = uuid.toString().getBytes();
        byte[] userdata = new byte[domainUsernameHash.length+password.length+ts.length+id.length];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(password, 0, userdata, domainUsernameHash.length, password.length);
        System.arraycopy(ts, 0, userdata, domainUsernameHash.length+password.length, ts.length);
        System.arraycopy(id, 0, userdata, domainUsernameHash.length+password.length+ts.length, id.length);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        domainUsernameHash[domainUsernameHash.length-domainUsernameHash.length/2] = flipBits(domainUsernameHash[domainUsernameHash.length-domainUsernameHash.length/2]);
        sc.put(nonce,domainUsernameHash,password,clientCert, signature, _timestamp, uuid.toString());
    }

    @org.junit.Test(expected = AuthenticationFailureException.class)
    public void putTamperedMessagePassword()throws Exception{
        byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(sc.getServerNonce()+1).array(), clientKey);
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());
        byte[] password = Cryptography.asymmetricCipher(PASSWORD_TO_STORE.getBytes(), clientCert.getPublicKey());

        UUID uuid = UUID.randomUUID();
        byte[] ts = ByteBuffer.allocate(Long.SIZE).putLong(++_timestamp).array();
        byte[] id = uuid.toString().getBytes();
        byte[] userdata = new byte[domainUsernameHash.length+password.length+ts.length+id.length];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(password, 0, userdata, domainUsernameHash.length, password.length);
        System.arraycopy(ts, 0, userdata, domainUsernameHash.length+password.length, ts.length);
        System.arraycopy(id, 0, userdata, domainUsernameHash.length+password.length+ts.length, id.length);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        password[password.length-password.length/2] = flipBits(password[password.length-password.length/2]);
        sc.put(nonce,domainUsernameHash,password,clientCert, signature, _timestamp, uuid.toString());
    }

    @org.junit.Test(expected = AuthenticationFailureException.class)
    public void putTamperedMessageSignature()throws Exception{
        byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(sc.getServerNonce()+1).array(), clientKey);
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());
        byte[] password = Cryptography.asymmetricCipher(PASSWORD_TO_STORE.getBytes(), clientCert.getPublicKey());

        UUID uuid = UUID.randomUUID();
        byte[] ts = ByteBuffer.allocate(Long.SIZE).putLong(++_timestamp).array();
        byte[] id = uuid.toString().getBytes();
        byte[] userdata = new byte[domainUsernameHash.length+password.length+ts.length+id.length];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(password, 0, userdata, domainUsernameHash.length, password.length);
        System.arraycopy(ts, 0, userdata, domainUsernameHash.length+password.length, ts.length);
        System.arraycopy(id, 0, userdata, domainUsernameHash.length+password.length+ts.length, id.length);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        signature[signature.length-signature.length/2] = flipBits(signature[signature.length-signature.length/2]);
        sc.put(nonce,domainUsernameHash,password,clientCert, signature, _timestamp, uuid.toString());
    }


    @org.junit.Test(expected = AuthenticationFailureException.class)
    public void getTamperedMessageUsername()throws Exception{
        int nonce = sc.getServerNonce()+1;
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());

        byte[] nonceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nonce).array();

        byte[] userdata = new byte[domainUsernameHash.length+NONCE_SIZE];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(nonceBytes, 0, userdata, domainUsernameHash.length, NONCE_SIZE);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        domainUsernameHash[domainUsernameHash.length-domainUsernameHash.length/2] = flipBits(domainUsernameHash[domainUsernameHash.length-domainUsernameHash.length/2]);

        PasswordResponse pw = sc.get(nonce, clientCert, domainUsernameHash, signature);



    }

    @org.junit.Test(expected = AuthenticationFailureException.class)
    public void getTamperedMessageSignature()throws Exception{
        int nonce = sc.getServerNonce()+1;
        byte[] domainUsernameHash = Cryptography.hash((DOMAIN+USERNAME).getBytes());

        byte[] nonceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nonce).array();

        byte[] userdata = new byte[domainUsernameHash.length+NONCE_SIZE];
        System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
        System.arraycopy(nonceBytes, 0, userdata, domainUsernameHash.length, NONCE_SIZE);

        byte[] signature = Cryptography.sign(userdata, clientKey);


        int myNounce = new SecureRandom().nextInt();
        byte[] response = sc.handshake(myNounce);

        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, serverCert.getPublicKey())).getInt();
        assertEquals(myNounce+1, decipheredResponse);

        signature[signature.length-signature.length/2] = flipBits(signature[signature.length-signature.length/2]);
        PasswordResponse pw = sc.get(nonce, clientCert, domainUsernameHash, signature);
    }

}