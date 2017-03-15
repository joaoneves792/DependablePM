package Crypto;

import javax.crypto.SecretKey;

import static org.junit.Assert.*;

/**
 * Created by joao on 3/9/17.
 */
public class CryptographyTest {
    private static final String PLAINTEXT = "Hi Alice, Im Bob.";

    @org.junit.Before
    public void setUp() throws Exception {

    }

    @org.junit.After
    public void tearDown() throws Exception {

    }

    /*TESTS*/
    /*Testing of this class is incomplete since most of the code originated from other projects where it was thoroughly tested,
    so here we only test the added/adapted methods
     */

    /*
    @org.junit.Test
    public void symmetricCipherWithPKCS5() throws Exception {
        SecretKey key = Cryptography.generateNewSymmetricKey();
        byte[] plaintext = PLAINTEXT.getBytes();
        byte[] ciphertext = Cryptography.symmetricCipherWithPKCS5(plaintext, key);
        byte[] decipheredtext = Cryptography.symmetricDecipherWithPKCS5(ciphertext, key);
        assertEquals(PLAINTEXT, new String(decipheredtext));
    }*/

}