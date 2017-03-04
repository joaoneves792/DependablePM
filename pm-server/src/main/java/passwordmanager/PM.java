package passwordmanager;
import java.rmi.*;
import java.rmi.server.UnicastRemoteObject;

public class PM extends UnicastRemoteObject implements PMService {
	int nonceC;
	int nonceS;

    public PM() throws RemoteException {}

	public String register() throws  RemoteException {
    	return "register not implemented";
	}

	public String handshake() throws RemoteException {
    	return "handshake not implemented";
	}
	public String getServerNonce() throws RemoteException {
		return "getServerNonce not implemented";
	}

	public String put() throws RemoteException {
		return "put not implemented";
	}
	public String get() throws RemoteException {
		return "get not implemented";
	}

}
