package passwordmanager;

import Crypto.exceptions.FailedToRetrieveKeyException;
import passwordmanager.exception.LibraryInitializationException;
import passwordmanager.exception.LibraryOperationException;
import passwordmanager.exception.SessionNotInitializedException;
import passwordmanager.exceptions.HandshakeFailedException;

import java.io.*;
import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;

/**
 * Created by goncalo on 07-03-2017.
 */
public class LibraryTest {
    private static PMLibraryImpl lib;

    // RIGHT VALUES
    private static final String CLIENT_RIGHT_KEYSTORE = "Client1";
    private static final String RIGHT_PASSWORD = "123456";
    private static final String RIGHT_CERT = "mycert";
    private static final String RIGHT_PRIVATEKEY_ALIAS = "mykey";
    private static final String RIGHT_SERVERCERT_ALIAS = "dependablepmserver";
    private static final String RIGHT_PASSWORD_TO_STORE = "strongpassword12345";
    private static final String RIGHT_DOMAIN = "fenix.tecnico.ulisboa.pt";
    private static final String RIGHT_USERNAME = "ist170666";

    // WRONG VALUES
    private static final String CLIENT_WRONG_KEYSTORE = "Client2";
    private static final String WRONG_PASSWORD = "1234567";
    private static final String WRONG_CERT = "mycert2";
    private static final String WRONG_PRIVATEKEY_ALIAS = "mykey2";
    private static final String WRONG_SERVERCERT_ALIAS = "dependablepmserver2";


    @org.junit.Before
    public void setUp() throws Exception {
        // Initialize Server
        PMService pm = (PMService) Naming.lookup("rmi://" + "localhost" +":"+2020+"/PMService");

        // Initialize Library
        lib = new PMLibraryImpl(pm);
    }


    private static KeyStore loadKeystore(String name, String password){
        String qq;

        FileInputStream fis;
        String filename = name + ".jks";
        try {
            fis = new FileInputStream(filename);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(fis, password.toCharArray());
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
    public void initSession() throws Exception{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);
    }

    @org.junit.Test
    public void registerUser() throws Exception{

        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Register user
        lib.register_user();
    }

    @org.junit.Test
    public void savedPassword() throws RemoteException, LibraryOperationException{

        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Register user
        lib.register_user();

        // Save a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);
    }

    @org.junit.Test
    public void retrievePassword() throws RemoteException, LibraryOperationException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Register user
        lib.register_user();

        // Save a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);

        // Get a password
        byte[] receivedPassword = lib.retrieve_password(domain, username);
        assertEquals(password, receivedPassword);
    }


    @org.junit.Test(expected = SessionNotInitializedException.class)
    public void sucessfullyCloseSession() throws RemoteException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Close session
        lib.close();

        // Try to make something
        lib.register_user();
    }

    @org.junit.Test
    public void closeSession() throws RemoteException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Close session
        lib.close();

    }



    /*-------------------------------------------------------------------------------------
    START OF NEGATIVE TESTING
    -------------------------------------------------------------------------------------*/

    @org.junit.Test(expected = LibraryInitializationException.class)
    public void failWrongServerAlias() throws RemoteException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, WRONG_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);
    }

    @org.junit.Test(expected = LibraryInitializationException.class)
    public void failWrongCertAlias() throws RemoteException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, WRONG_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

    }

    @org.junit.Test(expected = LibraryOperationException.class)
    public void failSaveWrongPrivKeyAlias() throws RemoteException, LibraryOperationException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, WRONG_PRIVATEKEY_ALIAS);

        // Register user
        lib.register_user();

        // Save a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);
    }

    @org.junit.Test(expected = LibraryOperationException.class)
    public void failSaveWrongPrivKeyPassword() throws RemoteException, LibraryOperationException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Register user
        lib.register_user();

        // Save a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);

        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);
    }


    @org.junit.Test(expected = SessionNotInitializedException.class)
    public void unintializedSessionWithPut() throws RemoteException, LibraryOperationException{
        lib.save_password(null, null, null);
    }

    @org.junit.Test(expected = SessionNotInitializedException.class)
    public void unintializedSessionWithGet() throws RemoteException, LibraryOperationException{
        lib.retrieve_password(null, null);
    }

    @org.junit.Test(expected = SessionNotInitializedException.class)
    public void unitializedSessionWithRegister() throws RemoteException, LibraryOperationException{
        lib.register_user();
    }
}
