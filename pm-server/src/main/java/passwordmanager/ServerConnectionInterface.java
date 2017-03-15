package passwordmanager;

import passwordmanager.exceptions.*;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;

public interface ServerConnectionInterface extends Remote {
  	void register(X509Certificate clientPublicKey) throws  RemoteException, UserAlreadyRegisteredException;

	byte[] handshake(int clientNonce) throws RemoteException, HandshakeFailedException;
	int getServerNonce() throws RemoteException;

	void put(byte[] nonce, byte[] domain, byte[] username, byte[] password, X509Certificate clientCert, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException;

	PasswordResponse get(int nonce, X509Certificate clientCert, byte[] domain, byte[] username, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException, UserNotRegisteredException, PasswordNotFoundException, StorageFailureException;
}
 
