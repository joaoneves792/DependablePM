package passwordmanager;

import java.util.Scanner;
import java.rmi.RemoteException;

public class PMLibrary {
    private PMService pm;
    private Scanner keyboardSc;

    private static final String INIT_REQ = "init";
    private static final String REGISTER_REQ = "register";
    private static final String SAVE_REQ = "save";
    private static final String RETRIEVE_REQ = "retrieve";
    private static final String CLOSE_REQ = "close";


    public PMLibrary(PMService pmService) throws RemoteException {
        pm = pmService;
        keyboardSc = new Scanner(System.in);
    }

    public void readRequest() throws RemoteException {
        //we have to define a syntax in which the client makes the requests based on our architecture
        //this is just for the first communication test, no arguments are being parsed
        String req;
        do {
            req = keyboardSc.nextLine();
            if (req.equals(INIT_REQ)) {
                init();
            } else if (req.equals(REGISTER_REQ)) {
                register();
            } else if (req.equals(SAVE_REQ)) {
                save();
            } else if (req.equals(RETRIEVE_REQ)) {
                retrieve();
            }
        } while (!req.equals(CLOSE_REQ));
        close();
    }

    //same thing as above, no arguments as of now, just testing the server
    private void init() throws RemoteException {
        System.out.println("init");
    }

    private void register() throws RemoteException {
        System.out.println(pm.register());
    }

    private void save() throws RemoteException {
        System.out.println(pm.put());
    }

    private void retrieve() throws RemoteException {
        System.out.println(pm.get());
    }

    private void close() throws RemoteException {
        System.out.println("close");
    }


}