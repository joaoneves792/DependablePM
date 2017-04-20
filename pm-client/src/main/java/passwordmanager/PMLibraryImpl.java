package passwordmanager;

import Crypto.Cryptography;
import Crypto.KeyManager;
import Crypto.exceptions.*;
import passwordmanager.exception.LibraryInitializationException;
import passwordmanager.exception.LibraryOperationException;
import passwordmanager.exception.ServerAuthenticationException;
import passwordmanager.exception.SessionNotInitializedException;
import passwordmanager.exceptions.*;


import java.net.MalformedURLException;
import java.nio.ByteBuffer;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;
import java.rmi.RemoteException;

public class PMLibraryImpl implements  PMLibrary{

    private static final int faults = 1;

    private ServerConnectionStub pm = null;


    public PMLibraryImpl() throws RemoteException {
    }

    @Override
    public void init(String keystoreName, String password, String certAlias, String serverAlias, String privKeyAlias) throws RemoteException {
        KeyManager km = KeyManager.getInstance(keystoreName, password);//Make sure the keystore has been initialized
        km.setAliases(certAlias, serverAlias, privKeyAlias); //Make sure we are using the correct aliases
        try{
            km.getServerCertificate();
            km.getMyCertificate();
            km.getMyPrivateKey();
        }catch (CertificateException |
                FailedToRetrieveKeyException |
                NoSuchAlgorithmException |
                UnrecoverableEntryException |
                KeyStoreException |
                SignatureException e){
            throw new LibraryInitializationException();
        }

        try{
            pm = new ServerConnectionStub(faults, keystoreName, password, certAlias, serverAlias, privKeyAlias);
        }catch(FailedToRetrieveKeyException e){
            throw new LibraryInitializationException();
        }

    }

    @Override
    public void register_user() throws RemoteException, LibraryOperationException {
        // Verifies if session was already initialized
        checkSession();

        // Register user at server using given certificate
        try{
            pm.register(KeyManager.getInstance().getMyCertificate());
        }catch (SignatureException | FailedToRetrieveKeyException | CertificateException e){
            throw new LibraryOperationException("Failed to use the local keystore...");
        }
    }

    @Override
    public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException, LibraryOperationException {
        // Verifies if session was already initialized
        checkSession();

        // Saves given password at server
        try{
            // Prepare arguments
            byte[] domainUsername = new byte[domain.length+username.length];
            System.arraycopy(domain, 0, domainUsername,0, domain.length);
            System.arraycopy(username, 0, domainUsername, domain.length, username.length);

            byte[] hashedDomainUsername = Cryptography.hash(domainUsername);
            byte[] cipheredPassword = Cryptography.asymmetricCipher(password, KeyManager.getInstance().getMyCertificate().getPublicKey());

            // Send request to server
            pm.put(hashedDomainUsername, cipheredPassword, KeyManager.getInstance().getMyCertificate());

        }catch(FailedToEncryptException e){
            throw new LibraryOperationException("Failure to encrypt data to sent to server", e);
        }catch(FailedToHashException e){
            throw new LibraryOperationException("Failure hashing data...", e);
        }catch (SignatureException | FailedToRetrieveKeyException | CertificateException e){
            throw new LibraryOperationException("Failed to use the local keystore...");
        }
    }

    @Override
    public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException, LibraryOperationException{
        try{
            checkSession();
            
            byte[] domainUsername = new byte[domain.length+username.length];
            System.arraycopy(domain, 0, domainUsername,0, domain.length);
            System.arraycopy(username, 0, domainUsername, domain.length, username.length);
            byte[] hashedDomainUsername = Cryptography.hash(domainUsername);

            // Make get request
            PasswordResponse passwordResponse;

            passwordResponse = pm.get(hashedDomainUsername);

            byte[] data = new byte[passwordResponse.domainUsernameHash.length + passwordResponse.password.length];
            System.arraycopy(passwordResponse.domainUsernameHash, 0, data, 0, passwordResponse.domainUsernameHash.length);
            System.arraycopy(passwordResponse.password, 0, data, passwordResponse.domainUsernameHash.length, passwordResponse.password.length);
            Cryptography.verifySignature(data, passwordResponse.signature, KeyManager.getInstance().getMyCertificate().getPublicKey());

            PrivateKey clientKey = KeyManager.getInstance().getMyPrivateKey();
            return Cryptography.asymmetricDecipher(passwordResponse.password, clientKey);

        }catch(HandshakeFailedException e){
            throw new LibraryOperationException("Failure in server handshaking", e);
        }catch(UnrecoverableEntryException e){
            throw new LibraryOperationException("Failure retrieving private key", e);
        }catch(SignatureException | FailedToVerifySignatureException | InvalidSignatureException e){
            throw new LibraryOperationException("Failure to validate the responses signature", e);
        }catch(FailedToRetrieveKeyException | NoSuchAlgorithmException | KeyStoreException e){
            throw new LibraryOperationException("Failure retrieving cryptographic material", e);
        }catch(AuthenticationFailureException e){
            throw new LibraryOperationException("Message invalid for server", e);
        }catch(FailedToHashException e){
            throw new LibraryOperationException("Failure hashing data...", e);
        }catch(StorageFailureException e){
            throw new LibraryOperationException("Failure accessing storage", e);
        }catch(UserNotRegisteredException e){
            throw new LibraryOperationException("User is not registered", e);
        }catch(PasswordNotFoundException e){
            throw new LibraryOperationException("Password not found", e);
        }catch(FailedToDecryptException e){
            System.out.println(e.toString());
            throw new LibraryOperationException(e.toString(), e);
        }catch (CertificateException e){
            throw new LibraryOperationException("Failed to retrieve cryptographic material from the keystore");
        }
    }

    private void checkSession(){
        if(null == pm){
            throw new SessionNotInitializedException("Session has not been initialized yet");
        }
    }

    @Override
    public void close() throws RemoteException {
        pm = null;
    }

}

