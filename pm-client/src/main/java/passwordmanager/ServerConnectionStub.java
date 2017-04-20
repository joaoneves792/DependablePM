package passwordmanager;

import Crypto.Cryptography;
import Crypto.KeyManager;
import Crypto.exceptions.FailedToDecryptException;
import Crypto.exceptions.FailedToRetrieveKeyException;
import passwordmanager.exception.LibraryOperationException;
import passwordmanager.exception.ServerAuthenticationException;
import passwordmanager.exceptions.*;

import java.net.MalformedURLException;
import java.nio.ByteBuffer;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.*;

/**
 * Created by joao on 4/20/17.
 */
public class ServerConnectionStub{
    private List<ServerConnectionInterface> _connections = new LinkedList<>();
    private static final int BASE_PORT = 2020;

    private static final int NONCE_SIZE = 4;

    private static Executor _ex;

    private int _serverCount = 1;
    private int _quorumCount = 0;

    ServerConnectionStub(int faults, String keystoreName, String password, String certAlias, String serverAlias, String privKeyAlias)throws RemoteException, FailedToRetrieveKeyException{
        _serverCount = 3*faults+1;
        _quorumCount = _serverCount; //TODO change this to actual value

        _ex = java.util.concurrent.Executors.newFixedThreadPool(_serverCount);

        try {
            for(int i=1; i<=_serverCount; i++) {
                int port = BASE_PORT+i;
                PMService pms = (PMService) Naming.lookup("rmi://" + "localhost" + ":" + port + "/PMService");
                _connections.add(pms.connect());
            }
        }catch (MalformedURLException | NotBoundException e){
            throw new RemoteException(e.getMessage(), e);
        }
    }

    public void register(X509Certificate clientPublicKey){
        for(ServerConnectionInterface sc : _connections) {
            try {
                sc.register(clientPublicKey);
            } catch (UserAlreadyRegisteredException | RemoteException e){
                //Empty on purpose
            }
        }
    }

    private int getServerNonce(ServerConnectionInterface server) throws RemoteException{
        return server.getServerNonce();
    }

    public void put(byte[] domainUsernameHash, byte[] password, X509Certificate clientCert)throws LibraryOperationException{

        class PutTask implements Callable<Void>{
            private byte[] _domainUsernameHash;
            private byte[] _password;
            private X509Certificate _clientCert;
            private ServerConnectionInterface _server;
            PutTask(byte[] duHash, byte[] pwd, X509Certificate cert, ServerConnectionInterface s){
                _domainUsernameHash = duHash;
                _password = pwd;
                _clientCert = cert;
                _server = s;
            }

            public Void call() throws Exception{
                authenticateServer(_server);
                PrivateKey clientKey = KeyManager.getInstance().getMyPrivateKey();
                byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(getServerNonce(_server) + 1).array(), clientKey);

                byte[] userdata = new byte[_domainUsernameHash.length + _password.length];
                System.arraycopy(_domainUsernameHash, 0, userdata, 0, _domainUsernameHash.length);
                System.arraycopy(_password, 0, userdata, _domainUsernameHash.length, _password.length);
                byte[] signature = Cryptography.sign(userdata, clientKey);

                _server.put(nonce, _domainUsernameHash, _password, _clientCert, signature);
                return null;
            }
        };

        CompletionService<Void> cs = new ExecutorCompletionService<Void>(_ex);
        for (ServerConnectionInterface server : _connections) {
            cs.submit(new PutTask(domainUsernameHash, password, clientCert, server));
        }

        int successfull = 0;

        for (int i=0; i<_serverCount; i++){
            if(successfull >= _quorumCount)
                break;
            try {
                cs.take().get();
                successfull++;
            }catch (InterruptedException e){
                --i; //Try again;
            }catch (ExecutionException e){
                //Empty on purpose Ignore if this call gave an exception
            }
        }

        if(successfull < _quorumCount) {
            throw new LibraryOperationException("Failed to store the password!");
        }
    }

    public PasswordResponse get(byte[] domainUsernameHash)throws RemoteException, LibraryOperationException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException, PasswordNotFoundException, StorageFailureException{
        PasswordResponse finalResponse = null;

        class GetTask implements Callable<PasswordResponse> {
            private byte[] _domainUsernameHash;
            private ServerConnectionInterface _server;

            GetTask(byte[] domainUsernameHash, ServerConnectionInterface server) {
                _domainUsernameHash = domainUsernameHash;
                _server = server;
            }

            public PasswordResponse call()throws Exception {
                    // First authenticate server
                    int initialNounce = authenticateServer(_server);

                    // Prepare arguments
                    int nounce = getServerNonce(_server) + 1;
                    byte[] nounceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nounce).array();

                    byte[] userdata = new byte[_domainUsernameHash.length + NONCE_SIZE];
                    System.arraycopy(_domainUsernameHash, 0, userdata, 0, _domainUsernameHash.length);
                    System.arraycopy(nounceBytes, 0, userdata, _domainUsernameHash.length, NONCE_SIZE);

                    PrivateKey clientKey = KeyManager.getInstance().getMyPrivateKey();
                    byte[] signature = Cryptography.sign(userdata, clientKey);

                    PasswordResponse response;
                    response = _server.get(nounce, KeyManager.getInstance().getMyCertificate(), _domainUsernameHash, signature);

                    byte[] decipheredNounceByte = Cryptography.asymmetricDecipher(response.nonce, KeyManager.getInstance().getServerCertificate().getPublicKey());
                    int passwordResponseNounce = ByteBuffer.wrap(decipheredNounceByte).getInt();
                    if (passwordResponseNounce != initialNounce + 2)
                        throw new AuthenticationFailureException("Bad nonce response.");
                    else
                        return response;
            }
        };

        CompletionService<PasswordResponse> cs = new ExecutorCompletionService<PasswordResponse>(_ex);
        for (ServerConnectionInterface server : _connections) {
            cs.submit(new GetTask(domainUsernameHash, server));
        }

        int successfull = 0;
        List<PasswordResponse> responses = new LinkedList<>();

        for (int i=0; i<_serverCount; i++){
            if(successfull >= _quorumCount)
                break;
            try {
                PasswordResponse r = cs.take().get();
                if(null != r){
                    responses.add(r);
                    successfull++;
                }
            }catch (InterruptedException e){
                --i; //Try again;
            }catch (ExecutionException e){
                //Empty on purpose Ignore all Exceptions
            }
        }

        if(successfull < _quorumCount) {
            throw new LibraryOperationException("Failed to retrieve the password!");
        }

        return responses.get(0);
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
