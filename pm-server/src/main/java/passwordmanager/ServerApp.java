package passwordmanager;
import Crypto.KeyManager;

import java.rmi.*;
import java.rmi.registry.*;

public class ServerApp {
	public static void main(String args[]){
		int registryPort = 2020;
        //System.setSecurityManager(new RMISecurityManager());
        System.out.println("Main OK");
        try{
            PMService pmService = new PM();
            System.out.println("After create");

        	Registry reg = LocateRegistry.createRegistry(registryPort);
			reg.rebind("PMService", pmService);

            System.out.println("Server ready");
        }catch(Exception e) {
            System.out.println("Server: " + e.getMessage());
        }
    }
}