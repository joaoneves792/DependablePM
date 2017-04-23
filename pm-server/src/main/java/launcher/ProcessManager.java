package launcher;

import java.io.IOException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Created by joao on 4/20/17.
 */
public class ProcessManager extends UnicastRemoteObject implements ProcessManagerInterface {

    private static final String BIN_PATH = "./target/appassembler/bin/pm-server";

    private int _faults;
    private String _keystorePassword;
    private int _desiredServerCount;
    private Map<Integer, Process> _processes = new HashMap<>();

    ProcessManager(int faults, String password)throws RemoteException{
        _faults = faults;
        _keystorePassword = password;
        _desiredServerCount = 3*_faults+1;
    }

    private void sleep(){
        try {
            Thread.sleep(1000);
        }catch (InterruptedException e){
            //Empty on purpose
        }
    }

    public void launchAll()throws RemoteException{
        if(_desiredServerCount == _processes.size()){
            return;
        }
        if(_processes.size() < _desiredServerCount && _processes.size() > 0){
            killAll();
        }
        System.out.println("Launching all processes...");
        try{
            for(int i = 1; i<= _desiredServerCount; i++){
                ProcessBuilder pb = new ProcessBuilder(BIN_PATH, _keystorePassword, String.valueOf(i));
                pb.inheritIO();
                _processes.put(i,pb.start());
            }
            sleep();

        }catch (IOException e){
            System.out.println("Failed to start servers!");
            killAll();
        }
    }

    public void killAll()throws RemoteException{
        System.out.println("Killing all processes...");
        for(Process p : _processes.values()){
            p.destroy();
        }
        _processes.clear();
        sleep();
    }

    public void killF()throws RemoteException{
        if(_desiredServerCount != _processes.size()){
            return;
        }
        for(int i=1; i<=_faults; i++){
            System.out.println("Killing process " + i);
            _processes.get(i).destroy();
            _processes.remove(i);
        }
        sleep();
    }

    public void killFplus1()throws RemoteException{
        if(_desiredServerCount != _processes.size()){
            return;
        }
        killF();
        System.out.println("Killing process " + (_faults+1));
        _processes.get(_faults+1).destroy();
        _processes.remove(_faults+1);

        sleep();
    }

}
