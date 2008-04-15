package org.example.code.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SymmetricCrypto {

    private static final Logger LOG = LoggerFactory.getLogger( SymmetricCrypto.class );
    private static final String ALGORITHM_NAME = "AES";
    private static final int ALGORITHM_BITS = 128;

    private final KeyGenerator keyGen;

    public SymmetricCrypto() {
        keyGen = loadKeyGenerator( ALGORITHM_NAME, ALGORITHM_BITS );
    }

    /**
     * Create a secret key that will be used during the symmetric encryption. The key will be an AES
     * key of 128bits (16bytes).
     */
    public SecretKey getAESSecret() {
        SecretKey secretKey = keyGen.generateKey();
        return secretKey;
    }

    public byte[] encrypt( byte[] data, SecretKey key ) throws CryptoException {
        return crypt( data, key, Cipher.ENCRYPT_MODE );
    }

    public byte[] decrypt( byte[] data, SecretKey key ) throws CryptoException {
        return crypt( data, key, Cipher.DECRYPT_MODE );
    }
    
    private byte[] crypt( byte[] data, SecretKey key, int mode ) throws CryptoException {
        byte[] result = null;
        
        try {
            Cipher aesCipher = Cipher.getInstance( ALGORITHM_NAME );

            /*
             * Step 3. Initialize the Cipher for Encryption
             */
            aesCipher.init( mode, key, aesCipher.getParameters() );

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
