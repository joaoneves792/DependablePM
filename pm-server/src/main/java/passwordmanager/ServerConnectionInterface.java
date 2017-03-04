package passwordmanager;

import passwordmanager.exceptions.AuthenticationFailureException;
import passwordmanager.exceptions.HandshakeFailedException;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;

public interface ServerConnectionInterface extends Remote {
  	String register(X509Certificate clientPublicKey) throws  RemoteException;

	byte[] handshake(int clientNonce) throws RemoteException, HandshakeFailedException;
	int getServerNonce() throws RemoteException;

	void put(byte[] nonce, byte[] domain, byte[] username, byte[] password, X509Certificate clientCert, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException;

	PasswordResponse get(int nonce, X509Certificate clientCert, byte[] domain, byte[] username, byte[] signature)throws RemoteException, HandshakeFailedException, AuthenticationFailureException;
}
 
