package passwordmanager;

import Crypto.Cryptography;
import Crypto.exceptions.FailedToRetrieveKeyException;
import mockit.Expectations;
import mockit.Mocked;
import passwordmanager.exception.LibraryInitializationException;
import passwordmanager.exception.LibraryOperationException;
import passwordmanager.exception.SessionNotInitializedException;
import passwordmanager.exceptions.HandshakeFailedException;
import passwordmanager.exceptions.UserNotRegisteredException;

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
import static org.junit.Assert.assertNotEquals;

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
        // Initialize Library
        lib = new PMLibraryImpl();

        // Register user
        try{
            // Initialize library
            lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

            lib.register_user();
        }catch(LibraryOperationException e){
            // Throw in case of UserAlreadyRegisteredException
            // Ignore and don't do anything
        }
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
    public void savedPassword() throws RemoteException, LibraryOperationException{
        // Save a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD_TO_STORE.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);
    }

    @org.junit.Test
    public void retrievePassword() throws RemoteException, LibraryOperationException{
        // Save a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD_TO_STORE.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);

        // Get a password
        byte[] receivedPassword = lib.retrieve_password(domain, username);
        String passwordReceived = new String(receivedPassword);
        String passwordSent = new String(password);
        assertEquals(passwordSent, passwordReceived);
    }

    @org.junit.Test
    public void sequentialPasswordWriting() throws RemoteException, LibraryOperationException{
        // The purpose of this test is to write two consequential passwords to the server
        // When we retrieve the password it must be equal to the last inserted password

        // Save correctly a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);

        // Save correctly another password
        domain = RIGHT_DOMAIN.getBytes();
        byte[] password2 = RIGHT_PASSWORD_TO_STORE.getBytes();
        username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password2);

        // Get a password
        byte[] receivedPassword = lib.retrieve_password(domain, username);
        String passwordReceived = new String(receivedPassword);
        String passwordSent = new String(password);
        String passwordSent2 = new String(password2);

        assertEquals(passwordSent2, passwordReceived);
        assertNotEquals(passwordSent, passwordReceived);
    }


    @org.junit.Test(expected = SessionNotInitializedException.class)
    public void sucessfullyCloseSession() throws RemoteException, LibraryOperationException{
        // Close session
        lib.close();

        // Try to make something
        lib.save_password(null, null, null);
    }

    @org.junit.Test
    public void closeSession() throws RemoteException{
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

    @org.junit.Test(expected = LibraryInitializationException.class)
    public void failWrongPrivKeyAlias() throws RemoteException, LibraryInitializationException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, WRONG_PRIVATEKEY_ALIAS);
    }

    @org.junit.Test(expected = LibraryInitializationException.class)
    public void failWrongPassword() throws RemoteException, LibraryInitializationException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, WRONG_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);
    }

    @org.junit.Test(expected = LibraryInitializationException.class)
    public void failSaveWrongPrivKeyPassword() throws RemoteException, LibraryOperationException, LibraryInitializationException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Save a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);

        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, WRONG_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Get a password
        byte[] receivedPassword = lib.retrieve_password(domain, username);
        assertEquals(password, receivedPassword);
    }

    @org.junit.Test(expected = SessionNotInitializedException.class)
    public void unintializedSessionWithPut() throws RemoteException, LibraryOperationException{
        lib.close();
        lib.save_password(null, null, null);
    }

    @org.junit.Test(expected = SessionNotInitializedException.class)
    public void unintializedSessionWithGet() throws RemoteException, LibraryOperationException{
        lib.close();
        lib.retrieve_password(null, null);
    }

    @org.junit.Test(expected = SessionNotInitializedException.class)
    public void unitializedSessionWithRegister() throws RemoteException, LibraryOperationException{
        lib.close();
        lib.register_user();
    }

    @org.junit.Test(expected = LibraryInitializationException.class)
    public void failRetrievePasswordWrongPassword() throws RemoteException, LibraryOperationException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Save correctly a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);

        // Now someone tries to ask for a password with invalid certificate values
        // In this case, the certificate is valid but the password for the private key isn't
        lib.init(CLIENT_RIGHT_KEYSTORE, WRONG_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Get a password
        byte[] receivedPassword = lib.retrieve_password(domain, username);
        String passwordReceived = new String(receivedPassword);
        String passwordSent = new String(password);
        assertEquals(passwordSent, passwordReceived);
    }

    @org.junit.Test(expected = LibraryInitializationException.class)
    public void failRetrievePasswordWrongCertAlias() throws RemoteException, LibraryOperationException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Save correctly a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);

        // Now someone tries to ask for a password with invalid certificate values
        // In this case, the certificate is valid but the server certificate alias is wrong
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, WRONG_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Get a password
        byte[] receivedPassword = lib.retrieve_password(domain, username);
        String passwordReceived = new String(receivedPassword);
        String passwordSent = new String(password);
        assertEquals(passwordSent, passwordReceived);
    }

    @org.junit.Test(expected = LibraryInitializationException.class)
    public void failRetrievePasswordWrongPrivKeyAlias() throws RemoteException, LibraryOperationException{
        // Initialize library
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, RIGHT_PRIVATEKEY_ALIAS);

        // Save correctly a password
        byte[] domain = RIGHT_DOMAIN.getBytes();
        byte[] password = RIGHT_PASSWORD.getBytes();
        byte[] username = RIGHT_USERNAME.getBytes();
        lib.save_password(domain, username, password);

        // Now someone tries to ask for a password with invalid certificate values
        // In this case, the certificate is valid but the alias for the private key isn't
        lib.init(CLIENT_RIGHT_KEYSTORE, RIGHT_PASSWORD, RIGHT_CERT, RIGHT_SERVERCERT_ALIAS, WRONG_PRIVATEKEY_ALIAS);

        // Get a password
        byte[] receivedPassword = lib.retrieve_password(domain, username);
        String passwordReceived = new String(receivedPassword);
        String passwordSent = new String(password);
        assertEquals(passwordSent, passwordReceived);
    }

}
