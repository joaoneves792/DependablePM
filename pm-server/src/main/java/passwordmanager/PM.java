package passwordmanager;
import java.rmi.*;
import java.rmi.server.UnicastRemoteObject;

public class PM extends UnicastRemoteObject implements PMService {
	boolean _emulateByzantine;

    public PM(boolean byzantine) throws RemoteException {
    	_emulateByzantine = byzantine;
	}

	public ServerConnectionInterface connect()throws RemoteException {
		if (_emulateByzantine){
			return new ByzantineServerConnection();
		}else{
			return new ServerConnection();
		}
	}
}
