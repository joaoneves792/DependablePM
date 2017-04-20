package passwordmanager;

import Crypto.Cryptography;
import Crypto.KeyManager;
import Crypto.exceptions.FailedToDecryptException;
import Crypto.exceptions.FailedToEncryptException;
import Crypto.exceptions.FailedToRetrieveKeyException;
import Crypto.exceptions.FailedToSignException;
import passwordmanager.exception.LibraryOperationException;
import passwordmanager.exception.ServerAuthenticationException;
import passwordmanager.exception.SessionNotInitializedException;
import passwordmanager.exceptions.*;

import javax.naming.AuthenticationException;
import java.net.MalformedURLException;
import java.nio.ByteBuffer;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Created by joao on 4/20/17.
 */
public class ServerConnectionStub{
    private List<ServerConnectionInterface> _connections = new LinkedList<>();
    private static final int BASE_PORT = 2020;

    private static final int NONCE_SIZE = 4;

    ServerConnectionStub(int faults, String keystoreName, String password, String certAlias, String serverAlias, String privKeyAlias)throws RemoteException, FailedToRetrieveKeyException{
        int serverCount = 3*faults+1;

        try {
            for(int i=1; i<=1; i++) {
                int port = BASE_PORT+i;
                PMService pms = (PMService) Naming.lookup("rmi://" + "localhost" + ":" + port + "/PMService");
                _connections.add(pms.connect());
            }
        }catch (MalformedURLException | NotBoundException e){
            throw new RemoteException(e.getMessage(), e);
        }
    }

    public void register(X509Certificate clientPublicKey) throws RemoteException, UserAlreadyRegisteredException{
        for(ServerConnectionInterface sc : _connections){
            sc.register(clientPublicKey);
        }
    }

    private int getServerNonce(ServerConnectionInterface server) throws RemoteException{
        return server.getServerNonce();
    }

    public void put(byte[] domainUsernameHash, byte[] password, X509Certificate clientCert)throws RemoteException, ServerAuthenticationException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException{
        try {
            for (ServerConnectionInterface server : _connections) {
                try {
                    authenticateServer(server);
                    PrivateKey clientKey = KeyManager.getInstance().getMyPrivateKey();
                    byte[] nounce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(getServerNonce(server) + 1).array(), clientKey);

                    byte[] userdata = new byte[domainUsernameHash.length + password.length];
                    System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
                    System.arraycopy(password, 0, userdata, domainUsernameHash.length, password.length);
                    byte[] signature = Cryptography.sign(userdata, clientKey);

                    server.put(nounce, domainUsernameHash, password, clientCert, signature);

                }catch (RemoteException |
                        ServerAuthenticationException |
                        HandshakeFailedException |
                        AuthenticationFailureException e){
                    //TODO handle individual Server failures
                }
            }
        }catch (FailedToDecryptException |
                NoSuchAlgorithmException |
                KeyStoreException |
                FailedToEncryptException |
                FailedToSignException |
                SignatureException |
                CertificateException |
                FailedToRetrieveKeyException |
                UnrecoverableEntryException e){
            throw new ServerAuthenticationException(e.getMessage());
        }
    }

    public PasswordResponse get(byte[] domainUsernameHash)throws RemoteException, LibraryOperationException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException, PasswordNotFoundException, StorageFailureException{
        PasswordResponse finalResponse = null;
        try {
            for (ServerConnectionInterface server : _connections) {
                try {
                    // First authenticate server
                    int initialNounce = authenticateServer(server);

                    // Prepare arguments
                    int nounce = getServerNonce(server) + 1;
                    byte[] nounceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nounce).array();

                    byte[] userdata = new byte[domainUsernameHash.length + NONCE_SIZE];
                    System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
                    System.arraycopy(nounceBytes, 0, userdata, domainUsernameHash.length, NONCE_SIZE);

                    PrivateKey clientKey = KeyManager.getInstance().getMyPrivateKey();
                    byte[] signature = Cryptography.sign(userdata, clientKey);

                    PasswordResponse response;
                    response = server.get(nounce, KeyManager.getInstance().getMyCertificate(), domainUsernameHash, signature);

                    byte[] decipheredNounceByte = Cryptography.asymmetricDecipher(response.nonce, KeyManager.getInstance().getServerCertificate().getPublicKey());
                    int passwordResponseNounce = ByteBuffer.wrap(decipheredNounceByte).getInt();
                    if (passwordResponseNounce != initialNounce + 2)
                        throw new AuthenticationFailureException("Bad nonce");
                    finalResponse = response;
                } catch (ServerAuthenticationException | FailedToDecryptException e) {
                    //TODO Logic for handling individual server failures
                }
            }
        }catch (NoSuchAlgorithmException |
                UnrecoverableEntryException |
                FailedToRetrieveKeyException |
                KeyStoreException |
                CertificateException |
                SignatureException |
                FailedToSignException e){
            throw new LibraryOperationException("Unrecoverable local failure", e);
        }
        return finalResponse;
    }

    private int authenticateServer(ServerConnectionInterface server) throws ServerAuthenticationException, RemoteException, HandshakeFailedException, FailedToDecryptException, CertificateException, SignatureException, FailedToRetrieveKeyException{
        int myNounce = new SecureRandom().nextInt();
        byte[] response = server.handshake(myNounce);
        int decipheredResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(response, KeyManager.getInstance().getServerCertificate().getPublicKey())).getInt();
        if(myNounce+1 != decipheredResponse){
            throw new ServerAuthenticationException("Server challenge not surpassed");
        }
        return myNounce;
    }

}
