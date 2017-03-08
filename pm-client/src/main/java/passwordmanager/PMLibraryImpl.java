package passwordmanager;

import Crypto.Cryptography;
import Crypto.exceptions.FailedToDecryptException;
import Crypto.exceptions.FailedToEncryptException;
import Crypto.exceptions.FailedToRetrieveKeyException;
import Crypto.exceptions.FailedToSignException;
import passwordmanager.exception.LibraryInitializationException;
import passwordmanager.exception.LibraryOperationException;
import passwordmanager.exception.ServerAuthenticationException;
import passwordmanager.exception.SessionNotInitializedException;
import passwordmanager.exceptions.AuthenticationFailureException;
import passwordmanager.exceptions.HandshakeFailedException;


import java.nio.ByteBuffer;
import java.security.*;
import java.util.Scanner;
import java.rmi.RemoteException;

public class PMLibraryImpl implements  PMLibrary{
    private static final int NONCE_SIZE = 4;

    private ServerConnectionInterface pm;
    private Scanner keyboardSc;
    private ConnectionState state = null;


    public PMLibraryImpl(PMService pmService) throws RemoteException {
        pm = pmService.connect();
    }

    @Override
    public void init(KeyStore keystore, String password, String certAlias, String serverAlias, String privKeyAlias) throws RemoteException {
        try{

            state = new ConnectionState(keystore);
            state.setKeyStore(keystore);
            state.initializeCertificates(certAlias, serverAlias);
            state.setPrivKeyAlias(privKeyAlias);
            state.setPassword(password);
        }catch(FailedToRetrieveKeyException e){
            throw new LibraryInitializationException();
        }

    }

    @Override
    public void register_user() throws RemoteException {
        // Verifies if session was already initialized
        checkSession();

        // Register user at server using given certificate
        pm.register(state.getClientCertificate());
    }

    @Override
    public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException, LibraryOperationException {
        // Verifies if session was already initialized
        checkSession();

        // Saves given password at server
        try{
            // First authenticate the server
            authenticateServer();

            // Prepare arguments
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(state.getPassword().toCharArray());
            PrivateKey clientKey = ((KeyStore.PrivateKeyEntry)(state.getKeyStore().getEntry(state.getPrivKeyAlias(), protParam))).getPrivateKey();
            byte[] nounce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(pm.getServerNonce()+1).array(), clientKey);
            byte[] cipheredUsername = Cryptography.asymmetricCipher(username, state.getClientCertificate().getPublicKey());
            byte[] cipheredDomain = Cryptography.asymmetricCipher(domain, state.getClientCertificate().getPublicKey());
            byte[] cipheredPassword = Cryptography.asymmetricCipher(password, state.getClientCertificate().getPublicKey());

            // Prepare signature of arguments
            byte[] userdata = new byte[cipheredDomain.length+cipheredUsername.length+cipheredPassword.length];
            System.arraycopy(cipheredDomain, 0, userdata, 0, cipheredDomain.length);
            System.arraycopy(cipheredUsername, 0, userdata, cipheredDomain.length, cipheredUsername.length);
            System.arraycopy(cipheredPassword, 0, userdata, cipheredDomain.length+cipheredUsername.length,
                    cipheredPassword.length);
            byte[] signature = Cryptography.sign(userdata, clientKey);

            // Send request to server
            pm.put(nounce, cipheredDomain, cipheredUsername, cipheredPassword, state.getClientCertificate(), signature);


        }catch(NoSuchAlgorithmException e){
            throw new LibraryOperationException("Failure retrieving private key", e);
        }catch(UnrecoverableEntryException e){
            throw new LibraryOperationException("Failure retrieving private key", e);
        }catch(KeyStoreException e){
            throw new LibraryOperationException("Failure retrieving private key", e);
        }catch(FailedToEncryptException e){
            throw new LibraryOperationException("Failure to encrypt data to sent to server", e);
        }catch(HandshakeFailedException e){
            throw new LibraryOperationException("Failure in server handshaking", e);
        }catch(FailedToSignException e){
            throw new LibraryOperationException("Failure signing data", e);
        }catch(AuthenticationFailureException e){
            throw new LibraryOperationException("Message invalid for server", e);
        }catch(ServerAuthenticationException e){
            throw new LibraryOperationException("Failure authenticating server", e);
        }
    }

    @Override
    public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException, LibraryOperationException{
        try{
            checkSession();
            
            // First authenticate server
            authenticateServer();

            // Prepare arguments
            byte[] cipheredUsername = Cryptography.asymmetricCipher(username, state.getClientCertificate().getPublicKey());
            byte[] cipheredDomain = Cryptography.asymmetricCipher(domain, state.getClientCertificate().getPublicKey());
            int nounce = pm.getServerNonce()+1; // Why not to cipher the nounce like we do in put?
            byte[] nounceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nounce).array();

            byte[] userdata = new byte[cipheredDomain.length+cipheredUsername.length+NONCE_SIZE];
            System.arraycopy(cipheredDomain, 0, userdata, 0, cipheredDomain.length);
            System.arraycopy(cipheredUsername, 0, userdata, cipheredDomain.length, cipheredUsername.length);
            System.arraycopy(nounceBytes, 0, userdata, cipheredDomain.length+cipheredUsername.length, NONCE_SIZE);

            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(state.getPassword().toCharArray());
            PrivateKey clientKey = ((KeyStore.PrivateKeyEntry)(state.getKeyStore().getEntry(state.getPrivKeyAlias(), protParam))).getPrivateKey();
            byte[] signature = Cryptography.sign(userdata, clientKey);

            // Make get request
            PasswordResponse passwordResponse;
            passwordResponse = pm.get(nounce, state.getClientCertificate(), cipheredDomain, cipheredUsername, signature);

            return passwordResponse.password;
        }catch(HandshakeFailedException e){
            throw new LibraryOperationException("Failure in server handshaking", e);
        }catch(ServerAuthenticationException e){
            throw new LibraryOperationException("Failure authenticating server", e);
        }catch(UnrecoverableEntryException e){
            throw new LibraryOperationException("Failure retrieving private key", e);
        }catch(NoSuchAlgorithmException e){
            throw new LibraryOperationException("Failure retrieving private key", e);
        }catch(KeyStoreException e){
            throw new LibraryOperationException("Failure retrieving private key", e);
        }catch(FailedToEncryptException e){
            throw new LibraryOperationException("Failure to encrypt data to sent to server", e);
        }catch(AuthenticationFailureException e){
            throw new LibraryOperationException("Message invalid for server", e);
        }catch(FailedToSignException e){
            throw new LibraryOperationException("Failure signing data", e);
        }
    }

    @Override
    public void close() throws RemoteException {
        state = null;
    }

    public void authenticateServer() throws ServerAuthenticationException, RemoteException, LibraryOperationException{
        try{
            int myNounce = new SecureRandom().nextInt();
            byte[] response = pm.handshake(myNounce);
            int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, state.getServerCertificate().getPublicKey())).getInt();
            if(myNounce+1 != decipheredResponse){
                throw new ServerAuthenticationException("Server challenge not surpassed");
            }
        }catch(HandshakeFailedException e){
            throw new LibraryOperationException("Failure authenticating server", e);
        }catch(FailedToDecryptException e){
            throw new LibraryOperationException("Failure decrypting server response", e);
        }
    }

    public void checkSession() throws SessionNotInitializedException{
        if(state == null)
            throw new SessionNotInitializedException("Session not yet initialized");
    }



}