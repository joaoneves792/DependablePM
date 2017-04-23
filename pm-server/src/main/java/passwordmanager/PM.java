package passwordmanager;
import java.rmi.*;
import java.rmi.server.UnicastRemoteObject;

public class PM extends UnicastRemoteObject implements PMService {

    public PM() throws RemoteException {}

	public ServerConnectionInterface connect()throws RemoteException{
    	return new ServerConnection();
	}
}
