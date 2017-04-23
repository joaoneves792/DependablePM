package passwordmanager;

import launcher.ProcessManagerInterface;
import passwordmanager.exception.LibraryInitializationException;
import passwordmanager.exception.LibraryOperationException;
import passwordmanager.exception.SessionNotInitializedException;

import java.rmi.Naming;
import java.rmi.RemoteException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by goncalo on 07-03-2017.
 */
public class ServerFaultTest {
    private static final int PROCESS_MANAGER_PORT = 2000;
    private static final String PROCESS_MANAGER_NAME = "ProcessManager";

    private LibraryTest libTest;
    private ProcessManagerInterface processManager;

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
    public void killFTest()throws Exception{
        processManager.killF();
        libTest.setUp();
        libTest.savedPassword();
        libTest.setUp();
        libTest.retrievePassword();
        libTest.setUp();
        libTest.sequentialPasswordWriting();
    }

    @org.junit.Test
    public void killFplus1Test()throws Exception{
        boolean caught = false;

        processManager.killFplus1();
        try {
            libTest.setUp();
        }catch (RemoteException e){
            //Its expected
            caught = true;
        }
        assertTrue(caught);
        caught = false;

        processManager.launchAll();
        libTest.setUp();
        processManager.killFplus1();

        try{
            libTest.savedPassword();
        }catch (LibraryOperationException e){
            //Its expected
            caught = true;
        }
        assertTrue(caught);
        caught = false;

        try{
            libTest.retrievePassword();
        }catch (LibraryOperationException e){
            //Its expected
            caught = true;
        }
        assertTrue(caught);
        caught = false;

        try{
            libTest.sequentialPasswordWriting();
        }catch (LibraryOperationException e){
            //Its expected
            caught = true;
        }
        assertTrue(caught);
        caught = false;
    }
}

