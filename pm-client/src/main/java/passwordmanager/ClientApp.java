package passwordmanager;
import java.rmi.*;

public class ClientApp {
	public static void main(String args[]) throws Exception {
   		//if (System.getSecurityManager() == null){
        //	System.setSecurityManager(new RMISecurityManager());
        //} else System.out.println("Already has a security manager, so cant set RMI SM");
		PMService pmService = null;
        try{
            pmService  = (PMService) Naming.lookup("rmi://" + "localhost" +":"+2020+"/PMService");
 			System.out.println("Found server");

 			PMLibrary lib = new PMLibrary(pmService);
			lib.readRequest();

		}catch(RemoteException e) {System.out.println(e.getMessage());
	    }catch(Exception e) {System.out.println(e.getMessage());}
    }
}