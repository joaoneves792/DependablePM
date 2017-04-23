package launcher;


import java.rmi.Remote;
import java.rmi.RemoteException;

public interface ProcessManagerInterface extends Remote {
	void launchAll()throws RemoteException;
	void killAll()throws RemoteException;
	void killF()throws RemoteException;
	void killFplus1()throws RemoteException;
	void makeFByzantine()throws RemoteException;
	void makeFplus1Byzantine()throws RemoteException;
}
 
