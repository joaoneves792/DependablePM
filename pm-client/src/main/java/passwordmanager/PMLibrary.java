package passwordmanager;

import passwordmanager.exception.LibraryOperationException;

import java.io.FileInputStream;
import java.rmi.RemoteException;
import java.security.KeyStore;

/**
 * Created by goncalo on 07-03-2017.
 */
public interface PMLibrary {
    void init(String keystoreName, String password, String certAlias, String serverAlias, String privKeyAlias) throws RemoteException;
    void register_user() throws RemoteException, LibraryOperationException;
    void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException, LibraryOperationException;
    byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException, LibraryOperationException;
    void close() throws RemoteException;
}
