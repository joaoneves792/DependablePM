package passwordmanager;

import Crypto.Cryptography;
import Crypto.KeyManager;
import Crypto.exceptions.FailedToEncryptException;
import passwordmanager.exceptions.*;

import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Random;


/*This is a class used only for testing that emulates a subset of behavior of a byzantine process by replying with trash
 * to get requests from clients (but otherwise respects the protocol)
 */

public class ByzantineServerConnection extends ServerConnection implements ServerConnectionInterface{
	private static final int NONCE_SIZE = 4;
	private static final String KEYSTORE = "DependablePMServer";

	public ByzantineServerConnection()throws RemoteException{
		super();
	}

	public void register(X509Certificate clientPublicKey) throws  RemoteException, UserAlreadyRegisteredException {
		//Do nothing
	}

	public void put(byte[] nonce, byte[] domainUsernameHash, byte[] password, X509Certificate clientCert, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException{
		//Do nothing

	}

	/*Byzantine behaving get*/
	public PasswordResponse get(int nonce, X509Certificate clientCert, byte[] domainUsernameHash, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException, PasswordNotFoundException, StorageFailureException{
	/*We generate a random password and signature but otherwise respect the protocol*/

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

		byte[] randomBuffer = new byte[256];
		Random rand = new Random();
		rand.nextBytes(randomBuffer);
		String fakePassword = Cryptography.encodeForStorage(randomBuffer);

		rand.nextBytes(randomBuffer);
		String fakeSignature = Cryptography.encodeForStorage(randomBuffer);

		Password pw = new Password(Cryptography.encodeForStorage(domainUsernameHash), fakePassword, fakeSignature, 0, "");

		return new PasswordResponse(pw, response);
	}

}
