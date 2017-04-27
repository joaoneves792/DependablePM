package passwordmanager;

import Crypto.Cryptography;
import Crypto.KeyManager;
import Crypto.exceptions.*;
import passwordmanager.exception.LibraryOperationException;
import passwordmanager.exception.ServerAuthenticationException;
import passwordmanager.exceptions.*;

import java.net.MalformedURLException;
import java.nio.ByteBuffer;
import java.rmi.ConnectException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
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
    private int _faults = 0;

    private long _timestamp = -1;
    UUID _uuid = UUID.randomUUID();

    ServerConnectionStub(int faults, String keystoreName, String password, String certAlias, String serverAlias, String privKeyAlias)throws RemoteException, FailedToRetrieveKeyException{
        _faults = faults;
        _serverCount = 3*faults+1;
        _quorumCount = ((_serverCount + faults)/2)+1;

        _ex = java.util.concurrent.Executors.newFixedThreadPool(_serverCount);

        int successfullCount = 0;
        for(int i=1; i<=_serverCount; i++) {
            int port = BASE_PORT+i;
            try {
                PMService pms = (PMService) Naming.lookup("rmi://" + "localhost" + ":" + port + "/PMService");
                _connections.add(pms.connect());

                successfullCount++;
            }catch (MalformedURLException | NotBoundException | ConnectException e){
                //Do nothing
            }
        }
        if(successfullCount < _quorumCount){
            throw new RemoteException("Not enough servers are available!");
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

    public void put(byte[] domainUsernameHash, byte[] password, X509Certificate clientCert)throws RemoteException, LibraryOperationException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException, StorageFailureException{
        try {
            PasswordResponse pw = get(domainUsernameHash, clientCert);
            _timestamp = pw.timestamp;
        }catch (LibraryOperationException e){
            _timestamp = 1;
        }
        put(domainUsernameHash, password, clientCert, ++_timestamp, _uuid.toString());

    }

    public void put(byte[] domainUsernameHash, byte[] password, X509Certificate clientCert, long timestamp, String uuid)throws LibraryOperationException{

        class PutTask implements Callable<Void>{
            private byte[] _domainUsernameHash;
            private byte[] _password;
            private X509Certificate _clientCert;
            private long _timestamp;
            private String _uuid;
            private ServerConnectionInterface _server;
            PutTask(byte[] duHash, byte[] pwd, X509Certificate cert, long times, String id, ServerConnectionInterface s){
                _domainUsernameHash = duHash;
                _password = pwd;
                _clientCert = cert;
                _timestamp = times;
                _uuid = id;
                _server = s;

            }

            public Void call() throws Exception{
                authenticateServer(_server);
                PrivateKey clientKey = KeyManager.getInstance().getMyPrivateKey();
                byte[] nonce = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(getServerNonce(_server) + 1).array(), clientKey);

                byte[] ts = ByteBuffer.allocate(Long.SIZE).putLong(_timestamp).array();
                byte[] id = _uuid.getBytes();

                byte[] userdata = new byte[_domainUsernameHash.length + _password.length + ts.length + id.length];
                System.arraycopy(_domainUsernameHash, 0, userdata, 0, _domainUsernameHash.length);
                System.arraycopy(_password, 0, userdata, _domainUsernameHash.length, _password.length);
                System.arraycopy(ts, 0, userdata, _domainUsernameHash.length+_password.length, ts.length);
                System.arraycopy(id, 0, userdata, _domainUsernameHash.length+_password.length+ts.length, id.length);
                byte[] signature = Cryptography.sign(userdata, clientKey);

                _server.put(nonce, _domainUsernameHash, _password, _clientCert, signature, _timestamp, _uuid);
                return null;
            }
        };

        CompletionService<Void> cs = new ExecutorCompletionService<Void>(_ex);
        for (ServerConnectionInterface server : _connections) {
            cs.submit(new PutTask(domainUsernameHash, password, clientCert, timestamp, uuid, server));
        }

        int successfull = 0;
        int failed = 0;

        for (int i=0; i<_serverCount; i++){
            if(successfull >= _quorumCount)
                break;
            try {
                cs.take().get();
                successfull++;
            }catch (InterruptedException |
                    ExecutionException e){
                if(++failed > _faults){
                    throw new LibraryOperationException("Failed to store the password!");
                }
            }
        }

        if(successfull < _quorumCount) {
            throw new LibraryOperationException("Failed to store the password!");
        }
    }

    public PasswordResponse get(byte[] domainUsernameHash, X509Certificate clientCert)throws RemoteException, LibraryOperationException{
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
        int failed = 0;
        List<PasswordResponse> responses = new LinkedList<>();


        for (int i=0; i<_serverCount; i++){
            if(successfull >= _quorumCount)
                break;
            try {
                PasswordResponse r = cs.take().get();
                if(null != r && verifyPasswordSignature(r)){
                    responses.add(r);
                    successfull++;
                }
            }catch (InterruptedException |
                    ExecutionException e){
                if(++failed > _faults){
                    throw new LibraryOperationException("Failed to retrieve the password!");
                }
            }
        }

        if(successfull < _quorumCount) {
            throw new LibraryOperationException("Failed to retrieve the password!");
        }

        PasswordResponse finalResponse = null;
        for(PasswordResponse pw : responses){
            if(null == finalResponse || pw.timestamp > finalResponse.timestamp){
                    finalResponse = pw;
            }
        }
        /* Use these prints to debug
        try {
            PrivateKey clientKey = KeyManager.getInstance().getMyPrivateKey();
            System.out.println(new String(Cryptography.asymmetricDecipher(finalResponse.password, clientKey)));
            System.out.println(finalResponse.timestamp);
            System.out.println(finalResponse.uuid);

        }catch (Exception e){}*/

        put(finalResponse.domainUsernameHash, finalResponse.password, clientCert, finalResponse.timestamp, finalResponse.uuid);

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


    private boolean verifyPasswordSignature(PasswordResponse pw) {
        try {

            byte[] ts = ByteBuffer.allocate(Long.SIZE).putLong(pw.timestamp).array();
            byte[] id = pw.uuid.getBytes();
            byte[] data = new byte[pw.domainUsernameHash.length + pw.password.length + ts.length + id.length];
            System.arraycopy(pw.domainUsernameHash, 0, data, 0, pw.domainUsernameHash.length);
            System.arraycopy(pw.password, 0, data, pw.domainUsernameHash.length, pw.password.length);
            System.arraycopy(ts, 0, data, pw.domainUsernameHash.length+pw.password.length, ts.length);
            System.arraycopy(id, 0, data, pw.domainUsernameHash.length+pw.password.length+ts.length, id.length);
            Cryptography.verifySignature(data, pw.signature, KeyManager.getInstance().getMyCertificate().getPublicKey());
            return true;
        } catch (SignatureException |
                FailedToVerifySignatureException |
                InvalidSignatureException |
                FailedToRetrieveKeyException |
                CertificateException e) {
            return false;
        }
    }
}
