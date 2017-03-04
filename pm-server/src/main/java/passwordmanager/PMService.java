package passwordmanager;
import java.rmi.*;

public interface PMService extends Remote {
  	String register() throws  RemoteException;

  	String handshake() throws RemoteException;
	String getServerNonce() throws RemoteException;

  	String put() throws RemoteException;
  	String get() throws RemoteException;
}
 
