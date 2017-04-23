package launcher;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * Created by joao on 4/20/17.
 */
public class ProcessLauncher{
    private static final int PORT = 2000;
    private static final String NAME = "ProcessManager";


    public static void main(String[] args){
        int faults = Integer.parseInt(args[0]);
        String keystorePassword = args[1];
        try {
            ProcessManagerInterface pm = new ProcessManager(faults, keystorePassword);

            Registry reg = LocateRegistry.createRegistry(PORT);
            reg.rebind(NAME, pm);

            pm.launchAll();
            System.out.println("Press ENTER to kill all servers.");
            System.in.read();
            pm.killAll();
        }catch (Exception e){
            System.out.println(e.getMessage());
        }
    }

}
