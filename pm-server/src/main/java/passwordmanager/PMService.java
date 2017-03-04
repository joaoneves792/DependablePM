package passwordmanager;
import java.rmi.*;

public interface PMService extends Remote {
	ServerConnectionInterface connect()throws RemoteException;
}
 
