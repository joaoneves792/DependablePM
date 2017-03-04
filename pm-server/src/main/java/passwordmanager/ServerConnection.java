package passwordmanager;

import Crypto.Cryptography;
import Crypto.KeyManager;
import Crypto.exceptions.FailedToDecryptException;
import Crypto.exceptions.FailedToEncryptException;
import Crypto.exceptions.FailedToVerifySignatureException;
import Crypto.exceptions.InvalidSignatureException;
import passwordmanager.exceptions.AuthenticationFailureException;
import passwordmanager.exceptions.HandshakeFailedException;

import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.X509Certificate;

public class ServerConnection extends UnicastRemoteObject implements ServerConnectionInterface{
	private static final int NONCE_SIZE = 4;
	private static final String KEYSTORE = "DependablePMServer.jks";

	private int _clientNonce;
	private int _serverNonce;

	private boolean _serverAuthenticationDone;

	public ServerConnection()throws RemoteException{
		_serverNonce = new SecureRandom().nextInt();
		_serverAuthenticationDone = false;
	}

	public String register(X509Certificate clientPublicKey) throws  RemoteException {
    	return "register not implemented";
	}

	public byte[] handshake(int clientNonce) throws RemoteException, HandshakeFailedException {
		PrivateKey serverPrivKey;
		try {
			KeyManager km = KeyManager.getInstance(KEYSTORE);
			serverPrivKey = km.getMyPrivateKey();
		}catch (NoSuchAlgorithmException |
				UnrecoverableEntryException |
				KeyStoreException e){
			throw new HandshakeFailedException("Failed to load the servers private key!", e);
		}

		_clientNonce = clientNonce;
		byte[] response;
		try {
			response = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(_clientNonce+1).array(), serverPrivKey);
		}catch (FailedToEncryptException e){
			throw new HandshakeFailedException("Failed to cipher the nonce response.", e);
		}
		_clientNonce += 1;
		_serverAuthenticationDone = true;
		return response;
	}
	public int getServerNonce()throws RemoteException{
		return _serverNonce;
	}

	public void put(byte[] nonce, byte[] domain, byte[] username, byte[] password, X509Certificate clientCert, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException{
		if (!_serverAuthenticationDone){
			throw new HandshakeFailedException("Handshake has not been successfully performed yet!");
		}

        /*First we make sure the message is Fresh!*/
		PublicKey clientPubKey = clientCert.getPublicKey();
		int clientResponse;
		try{
			clientResponse = ByteBuffer.wrap(Cryptography.asymmetricDecipher(nonce, clientPubKey)).getInt();
			if(clientResponse != _serverNonce+1){
				throw new AuthenticationFailureException("Client response is invalid!");
			}else{
				_serverNonce += 1;
			}
		}catch (FailedToDecryptException e) {
			throw new AuthenticationFailureException("Could not decipher client response!");
		}

        /*Now we make sure the message has not been tampered with!*/
		byte[] userdata = new byte[domain.length+username.length+password.length];
		System.arraycopy(domain, 0, userdata, 0, domain.length);
		System.arraycopy(username, 0, userdata, domain.length, username.length);
		System.arraycopy(password, 0, userdata, domain.length+username.length, password.length);

		try {
			Cryptography.verifySignature(userdata, signature, clientPubKey);
		}catch (FailedToVerifySignatureException | InvalidSignatureException e){
			throw new AuthenticationFailureException("Failed to verify clients signature!", e);
		}

        /*OK now we are in the clear! All we need to do is store the domain, username, password and signature!*/
		//TODO: Read line above
	}

	public PasswordResponse get(int nonce, X509Certificate clientCert, byte[] domain, byte[] username, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException{
		if (!_serverAuthenticationDone){
			throw new HandshakeFailedException("Handshake has not been successfully performed yet!");
		}

        /*First we make sure the message is Fresh!*/
		if(nonce != _serverNonce+1){
			throw new AuthenticationFailureException("Client response is invalid!");
		}else{
			_serverNonce += 1;
		}

        /*Now we make sure the message has not been tampered with!*/
		PublicKey clientPubKey = clientCert.getPublicKey();

		byte[] nonceBytes = ByteBuffer.allocate(NONCE_SIZE).putInt(nonce).array();

		byte[] userdata = new byte[domain.length+username.length+NONCE_SIZE];
		System.arraycopy(domain, 0, userdata, 0, domain.length);
		System.arraycopy(username, 0, userdata, domain.length, username.length);
		System.arraycopy(nonceBytes, 0, userdata, domain.length+username.length, NONCE_SIZE);
		try {
			Cryptography.verifySignature(userdata, signature, clientPubKey);
		}catch (FailedToVerifySignatureException | InvalidSignatureException e){
			throw new AuthenticationFailureException("Failed to verify clients signature!", e);
		}

        /*OK now we are in the clear! All we need to do is retrieve the password*/
		//TODO: Read line above

        /*Finally we put everything into a PasswordResponse including the nonce for freshness!*/
		PrivateKey serverPrivKey;
		try {
			KeyManager km = KeyManager.getInstance(KEYSTORE);
			serverPrivKey = km.getMyPrivateKey();
		}catch (NoSuchAlgorithmException|
				UnrecoverableEntryException|
				KeyStoreException e){
			throw new HandshakeFailedException("Failed to load the servers private key!", e);
		}

		byte[] response;
		try {
			response = Cryptography.asymmetricCipher(ByteBuffer.allocate(NONCE_SIZE).putInt(_clientNonce+1).array(), serverPrivKey);
		}catch (FailedToEncryptException e){
			throw new HandshakeFailedException("Failed to cipher the nonce response.", e);
		}
		_clientNonce += 1;


		return new PasswordResponse(response);
	}

}
