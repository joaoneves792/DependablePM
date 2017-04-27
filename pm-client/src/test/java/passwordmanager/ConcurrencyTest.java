package passwordmanager;

import launcher.ProcessManagerInterface;
import passwordmanager.exception.LibraryOperationException;

import javax.swing.*;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.*;

import static org.junit.Assert.assertTrue;

/**
 * Created by goncalo on 07-03-2017.
 */
public class ConcurrencyTest {
    private static final int PROCESS_MANAGER_PORT = 2000;
    private static final String PROCESS_MANAGER_NAME = "ProcessManager";


    private static final int CONCURRENCY_LEVEL = 3;
    private static final int CONSECUTIVE_OPERATIONS = 100;


    private static final String CLIENT_ID = "C";
    private static final String SEPARATOR = "_";

    private LibraryTest libTest;
    private ProcessManagerInterface processManager;
    private static Executor ex = java.util.concurrent.Executors.newFixedThreadPool(CONCURRENCY_LEVEL);

    @org.junit.Before
    public void setUp() throws Exception {
        libTest = new LibraryTest();
        processManager = (ProcessManagerInterface) Naming.lookup("rmi://" + "localhost" + ":" + PROCESS_MANAGER_PORT + "/" + PROCESS_MANAGER_NAME);
        processManager.launchAll();
    }

    @org.junit.After
    public void tearDown()throws Exception{
        processManager.launchAll();
    }


    @org.junit.Test
    public void concurrentWritesTest()throws Exception{
        class ClientTask implements Callable<Void> {
            private Integer _id;
            //This map should contain the last password (in fact just the counter) seen from every originating process.
            private Map<Integer, Integer> seenPasswords = new HashMap<>();
            private Integer _counter;

            ClientTask(Integer id) {
                _id = id;
                _counter = 0;
            }

            public Void call() throws Exception {
                PMLibrary lib = new PMLibraryImpl();

                lib.init(LibraryTest.CLIENT_RIGHT_KEYSTORE, LibraryTest.RIGHT_PASSWORD, LibraryTest.RIGHT_CERT, LibraryTest.RIGHT_SERVERCERT_ALIAS, LibraryTest.RIGHT_PRIVATEKEY_ALIAS);
                try {
                    lib.register_user();
                }catch (LibraryOperationException e){
                    //Ignore if user is already registered
                }

                for(int i=0; i<CONSECUTIVE_OPERATIONS; i++) {
                    byte[] password = (_id + SEPARATOR + (++_counter)).getBytes();

                    lib.save_password(LibraryTest.RIGHT_DOMAIN.getBytes(), LibraryTest.RIGHT_USERNAME.getBytes(), password);
                    Thread.sleep(ThreadLocalRandom.current().nextInt(0, 50));
                    String responsePassword = new String(lib.retrieve_password(LibraryTest.RIGHT_DOMAIN.getBytes(), LibraryTest.RIGHT_USERNAME.getBytes()));

                    String[] parts = responsePassword.split(SEPARATOR);
                    int origin = Integer.parseInt(parts[0]);
                    int version = Integer.parseInt(parts[1]);

                    //System.out.println(responsePassword);

                    if(seenPasswords.containsKey(origin)) {
                        assertTrue("Got an old value!", seenPasswords.get(origin) <= version);
                    }
                    seenPasswords.put(origin, version);

                    Thread.sleep(ThreadLocalRandom.current().nextInt(0, 50));
                }

                return null;
            }
        }

        CompletionService<Void> cs = new ExecutorCompletionService<Void>(ex);
        for (int i=0; i<CONCURRENCY_LEVEL; i++) {
            cs.submit(new ClientTask(i));
        }


        for (int i=0; i<CONCURRENCY_LEVEL; i++) {
            cs.take().get();
        }

    }

}

