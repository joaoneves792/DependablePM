package launcher;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

/**
 * Created by joao on 4/20/17.
 */
public class ProcessLauncher {

    private static final String BIN_PATH = "./target/appassembler/bin/pm-server";

    public static void main(String[] args){
        int faults = Integer.parseInt(args[0]);
        String keystorePassword = args[1];

        int serverCount = 3*faults+1;

        List<Process> processes = new LinkedList<>();

        try{
            for(int i = 1; i<= serverCount; i++){
                ProcessBuilder pb = new ProcessBuilder(BIN_PATH, keystorePassword, String.valueOf(i));
                pb.inheritIO();
                processes.add(pb.start());
            }

            Thread.sleep(1000);
            System.out.println("Press ENTER to kill all servers.");
            System.in.read();
            for(Process p : processes){
                p.destroy();
            }

        }catch (IOException | InterruptedException e){
            System.out.println("Failed to start servers!");
            for(Process p : processes){
                p.destroy();
            }
        }
    }

}
