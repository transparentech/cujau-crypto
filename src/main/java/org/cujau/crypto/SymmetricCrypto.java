package org.cujau.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SymmetricCrypto {

    private static final Logger LOG = LoggerFactory.getLogger( SymmetricCrypto.class );
    
    static final String ALGORITHM_NAME = "AES";
    static final String CIPHER_ALGORITHM_NAME = "AES/CBC/PKCS5Padding";
    static final int ALGORITHM_BITS = 128;

    private final KeyGenerator keyGen;
    private final SecureRandom secureRandom;

    public SymmetricCrypto() throws CryptoException {
        keyGen = loadKeyGenerator( ALGORITHM_NAME, ALGORITHM_BITS );
        
        try {
            secureRandom = SecureRandom.getInstance( "SHA1PRNG" );
        } catch ( NoSuchAlgorithmException e ) {
            throw new CryptoException( e );
        }
    }

    /**
     * Create a random secret key that will be used during the symmetric encryption. The key will be
     * an AES key of 128bits (16bytes).
     */
    public SecretKey getRandomKey() {
        SecretKey secretKey = keyGen.generateKey();
        return secretKey;
    }

    public SecretKey getKeyFromBytes( byte[] key ) {
        return new SecretKeySpec( key, ALGORITHM_NAME );
    }

    /**
     * Create a random IV that will be used during the symmetric encryption. The IV will contain 16
     * random bytes.
     * 
     * @return A random IvParameterSpec
     * @throws CryptoException
     *             If the "SHA1PRNG" algorithm is not available.
     */
    public IvParameterSpec getRandomIV() {
        byte[] iv = new byte[16];
        secureRandom.nextBytes( iv );
        return new IvParameterSpec( iv );
    }

    public IvParameterSpec getIvFromBytes( byte[] iv ) {
        return new IvParameterSpec( iv );
    }

    public byte[] encrypt( byte[] data, SecretKey key, IvParameterSpec iv )
            throws CryptoException {
        return crypt( data, key, iv, Cipher.ENCRYPT_MODE );
    }

    public byte[] decrypt( byte[] data, SecretKey key, IvParameterSpec iv )
            throws CryptoException {
        return crypt( data, key, iv, Cipher.DECRYPT_MODE );
    }

    private byte[] crypt( byte[] data, SecretKey key, IvParameterSpec iv, int mode )
            throws CryptoException {
        byte[] result = null;

        try {
            Cipher aesCipher = Cipher.getInstance( CIPHER_ALGORITHM_NAME );

            /*
             * Step 3. Initialize the Cipher for Encryption
             */
            aesCipher.init( mode, key, iv );

            /**
             * Step 4. Encrypt the Data 1. Declare / Initialize the Data. Here the data is of type
             * String 2. Convert the Input Text to Bytes 3. Encrypt the bytes using doFinal method
             */
            result = aesCipher.doFinal( data );
        } catch ( NoSuchAlgorithmException e ) {
            throw new CryptoException( e );
        } catch ( NoSuchPaddingException e ) {
            throw new CryptoException( e );
        } catch ( InvalidKeyException e ) {
            throw new CryptoException( e );
        } catch ( InvalidAlgorithmParameterException e ) {
            throw new CryptoException( e );
        } catch ( IllegalBlockSizeException e ) {
            throw new CryptoException( e );
        } catch ( BadPaddingException e ) {
            throw new CryptoException( e );
        }

        return result;
    }

    private static KeyGenerator loadKeyGenerator( String algo, int size ) {
        KeyGenerator gen = null;
        try {
            gen = KeyGenerator.getInstance( algo );
            gen.init( size );
        } catch ( NoSuchAlgorithmException e ) {
            LOG.error( "{} is not supported!", algo );
            LOG.error( "Error is: ", e );
        }
        return gen;
    }

}
