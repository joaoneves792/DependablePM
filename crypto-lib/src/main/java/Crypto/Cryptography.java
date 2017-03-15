package Crypto;

import Crypto.exceptions.*;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;


/**
 * Created by joao on 11/21/15.
 */
public class Cryptography {
    private static final int IV_SIZE = 16;
    private static final int AES_KEY_SIZE = 256;

    public static byte[] symmetricCipher(byte[] plainText, SecretKey key, String algorithm, byte[] iv) throws FailedToEncryptException {
        try{
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            Cipher aesCipher = Cipher.getInstance(algorithm);
            aesCipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
            byte[] cipherText = aesCipher.doFinal(plainText);

            byte[] ivPlusCipherText = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, ivPlusCipherText, 0, iv.length);
            System.arraycopy(cipherText, 0, ivPlusCipherText, iv.length, cipherText.length);

            return ivPlusCipherText;
        } catch (InvalidKeyException
                | NoSuchAlgorithmException
                | NoSuchPaddingException
                | IllegalBlockSizeException
                | InvalidAlgorithmParameterException
                | BadPaddingException exception){
            throw new FailedToEncryptException(exception);
        }
    }

    public static byte[] symmetricCipherWithCTS(byte[] plainText, SecretKey key)throws FailedToEncryptException{
        SecureRandom random = new SecureRandom();
        byte iv[] = new byte[IV_SIZE];
        random.nextBytes(iv);
        return symmetricCipher(plainText, key, "AES/CBC/withCTS", iv);
    }

    public static byte[] symmetricCipherWithPKCS5(byte[] plainText, SecretKey key)throws FailedToEncryptException{
        SecureRandom random = new SecureRandom();
        byte iv[] = new byte[IV_SIZE];
        random.nextBytes(iv);
        return symmetricCipher(plainText, key, "AES/CBC/PKCS5Padding", iv);
    }


    public static byte[] symmetricDecipher(byte[] cipheredData, SecretKey key, String algorithm)throws FailedToDecryptException {
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(cipheredData,0, iv, 0, IV_SIZE);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        byte[] cipheredMessage = new byte[cipheredData.length-IV_SIZE];
        System.arraycopy(cipheredData, IV_SIZE, cipheredMessage, 0, cipheredData.length-IV_SIZE);

        try{
            Cipher aesCipher = Cipher.getInstance(algorithm);
            aesCipher.init(Cipher.DECRYPT_MODE, key, ivspec);
            return aesCipher.doFinal(cipheredMessage);
        } catch (InvalidKeyException
                | NoSuchAlgorithmException
                | NoSuchPaddingException
                | IllegalBlockSizeException
                | InvalidAlgorithmParameterException
                | BadPaddingException exception){
            throw new FailedToDecryptException(exception);
        }
    }

    public static byte[] symmetricDecipherWithCTS(byte[] plainText, SecretKey key)throws FailedToDecryptException{
        return symmetricDecipher(plainText, key, "AES/CBC/withCTS");
    }

    public static byte[] symmetricDecipherWithPKCS5(byte[] plainText, SecretKey key)throws FailedToDecryptException{
        return symmetricDecipher(plainText, key, "AES/CBC/PKCS5Padding");
    }

    public static byte[] asymmetricCipher(byte[] plainText, Key key)throws FailedToEncryptException{
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plainText);
        }catch(NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidKeyException
                | IllegalBlockSizeException
                | BadPaddingException exception){
            throw new FailedToEncryptException(exception);
        }
    }

    public static byte[] asymmetricDecipher(byte[] cipheredData, Key key)throws FailedToDecryptException{
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(cipheredData);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidKeyException
                | IllegalBlockSizeException
                | BadPaddingException exception){
            throw new FailedToDecryptException(exception);
        }
    }

/*
    public static byte[] passwordCipher (byte[] plainText, byte[] salt, byte[] iv) throws FailedToEncryptException {

        try {
            //generate key
            KeyManager km = KeyManager.getInstance();
            SecretKey secretKey = km.generateStorageKey(salt);
            //encrypt data
            return Crypto.Cryptography.symmetricCipherWithPKCS5(plainText, secretKey, iv);
        } catch (NullPointerException
                | KeyStoreIsLockedException
                | FailedToGenerateKeyException
                | FailedToStoreException exception){
            throw new FailedToEncryptException(exception);
        }
    }

    public static byte[] passwordDecipher(byte[] cipherData, byte[] salt, byte[] iv) throws FailedToDecryptException {
        try {
            KeyManager km = KeyManager.getInstance();
            SecretKey secretKey = km.generateStorageKey(salt);
            //encrypt data
            return Crypto.Cryptography.symmetricDecipherWithPKCS5(cipherData, secretKey, iv); // or use algorithm "AES/ECB/PKCS5Padding"
        } catch (NullPointerException
                | KeyStoreIsLockedException
                | FailedToGenerateKeyException
                | FailedToStoreException exception){
            throw new FailedToDecryptException(exception);
        }
    }
*/

    public static byte[] sign(byte[] message, PrivateKey key)throws FailedToSignException {
        try{
            Signature dsa = Signature.getInstance("SHA256withRSA");
            dsa.initSign(key);
            dsa.update(message);
            return dsa.sign();
        }catch (NoSuchAlgorithmException
                | InvalidKeyException
                | SignatureException exception){
            throw new FailedToSignException(exception);
        }
    }

    public static void verifySignature(byte[] message, byte[] signature, PublicKey key)throws FailedToVerifySignatureException, InvalidSignatureException {
        try{
            Signature dsa = Signature.getInstance("SHA256withRSA");
            dsa.initVerify(key);
            dsa.update(message);
            if(!dsa.verify(signature))
                throw new InvalidSignatureException();
        }catch (NoSuchAlgorithmException
                | InvalidKeyException
                | SignatureException exception){
            throw new FailedToVerifySignatureException(exception);
        }
    }

    public static byte[] hash(byte[] message) throws FailedToHashException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            md.update(message);
            byte[] messageDigest = md.digest();
            return messageDigest;
        } catch ( NoSuchAlgorithmException exception) {
            throw new FailedToHashException(exception);
        }
    }

    public static SecretKey generateNewSymmetricKey() throws FailedToGenerateKeyException{
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE, new SecureRandom());
            return keyGen.generateKey();
        }catch (NoSuchAlgorithmException e){
            throw new FailedToGenerateKeyException("AES cipher is not available", e);
        }
    }

    /*
    public static byte[] encode(String message) {
        return message.getBytes(Charset.defaultCharset());
    }
    public static String decode(byte[] message) {
        return new String(message, Charset.defaultCharset());
    }
*/
    public static String encodeForStorage(byte[] message) {
        return Base64.getEncoder().encodeToString(message);
    }
    public static byte[] decodeFromStorage(String message) {
        return Base64.getDecoder().decode(message);
    }

}
