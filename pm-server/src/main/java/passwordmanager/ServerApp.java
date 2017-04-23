package passwordmanager;
import Crypto.KeyManager;

import java.rmi.*;
import java.rmi.registry.*;

public class ServerApp {
    private static final String KEYSTORE = "DependablePMServer";

	public static void main(String args[]){
		int baseRegistryPort = 2020;

		if(args.length < 1) {
            System.out.println("You have to supply the Keystore password as an argument. Aborting!");
            System.exit(-1);
        }
        if(args.length < 2){
            System.out.println("You have to supply an offset for the port (2020+offset). Aborting!");
            System.exit(-1);
        }

        int registryPort = baseRegistryPort + Integer.parseInt(args[1]);

        //System.setSecurityManager(new RMISecurityManager());
        try{
            //Load the keystore with the password so we dont need to propagate the password
            KeyManager.getInstance(KEYSTORE, args[0]);

            PMService pmService;
            if(args.length > 2 && args[3].equals("true")){
                pmService = new PM(true);
            }else {
                pmService = new PM(false);
            }
        	Registry reg = LocateRegistry.createRegistry(registryPort);
			reg.rebind("PMService", pmService);

            System.out.println("Server ready, Listening on port: " + registryPort);
        }catch(Exception e) {
            System.out.println("Server: " + e.getMessage());
        }
    }
}