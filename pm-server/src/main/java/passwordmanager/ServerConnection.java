package passwordmanager;

import Crypto.Cryptography;
import Crypto.KeyManager;
import Crypto.exceptions.FailedToDecryptException;
import Crypto.exceptions.FailedToEncryptException;
import Crypto.exceptions.FailedToVerifySignatureException;
import Crypto.exceptions.InvalidSignatureException;
import passwordmanager.exceptions.*;

import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.X509Certificate;

public class ServerConnection extends UnicastRemoteObject implements ServerConnectionInterface{
	private static final int NONCE_SIZE = 4;
	private static final String KEYSTORE = "DependablePMServer";

	private int _clientNonce;
	private int _serverNonce;

	private boolean _serverAuthenticationDone;

	public ServerConnection()throws RemoteException{
		_serverNonce = new SecureRandom().nextInt();
		_serverAuthenticationDone = false;
	}

	public void register(X509Certificate clientPublicKey) throws  RemoteException, UserAlreadyRegisteredException {
		PasswordStore.getInstance().register(clientPublicKey.getPublicKey());
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

	public void put(byte[] nonce, byte[] domainUsernameHash, byte[] password, X509Certificate clientCert, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException{
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
		byte[] userdata = new byte[domainUsernameHash.length+password.length];
		System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
		System.arraycopy(password, 0, userdata, domainUsernameHash.length, password.length);

		try {
			Cryptography.verifySignature(userdata, signature, clientPubKey);
		}catch (FailedToVerifySignatureException | InvalidSignatureException e){
			throw new AuthenticationFailureException("Failed to verify clients signature!", e);
		}

		PasswordStore.getInstance().storePassword(clientPubKey, domainUsernameHash, password, signature);
	}

	public PasswordResponse get(int nonce, X509Certificate clientCert, byte[] domainUsernameHash, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException, PasswordNotFoundException, StorageFailureException{
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

		byte[] userdata = new byte[domainUsernameHash.length+NONCE_SIZE];
		System.arraycopy(domainUsernameHash, 0, userdata, 0, domainUsernameHash.length);
		System.arraycopy(nonceBytes, 0, userdata, domainUsernameHash.length, NONCE_SIZE);
		try {
			Cryptography.verifySignature(userdata, signature, clientPubKey);
		}catch (FailedToVerifySignatureException | InvalidSignatureException e){
			throw new AuthenticationFailureException("Failed to verify clients signature!", e);
		}

		Password pw = PasswordStore.getInstance().getPassword(clientPubKey, domainUsernameHash);
        /*Now we make sure the storage has not been tampered with!*/
		byte[] storeduserdata = new byte[pw.get_domainUsernameHash().length+pw.get_password().length];
		System.arraycopy(pw.get_domainUsernameHash(), 0, storeduserdata, 0, pw.get_domainUsernameHash().length);
		System.arraycopy(pw.get_password(), 0, storeduserdata, pw.get_domainUsernameHash().length, pw.get_password().length);

		try {
			Cryptography.verifySignature(storeduserdata, pw.get_signature(), clientPubKey);
		}catch (FailedToVerifySignatureException | InvalidSignatureException e){
			throw new StorageFailureException("Failed to verify clients signature on the stored data!", e);
		}


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


		return new PasswordResponse(pw, response);
	}

}
