package passwordmanager;

import passwordmanager.exceptions.*;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;

public interface ServerConnectionInterface extends Remote {
  	void register(X509Certificate clientPublicKey) throws  RemoteException, UserAlreadyRegisteredException;

	byte[] handshake(int clientNonce) throws RemoteException, HandshakeFailedException;
	int getServerNonce() throws RemoteException;

	void put(byte[] nonce, byte[] domainUsernameHash, byte[] password, X509Certificate clientCert, byte[] signature, long timestamp)throws RemoteException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException;

	PasswordResponse get(int nonce, X509Certificate clientCert, byte[] domainUsernameHash, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException, PasswordNotFoundException, StorageFailureException;
}
 
