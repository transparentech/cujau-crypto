package org.cujau.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AsymmetricCrypto {

    private static final Logger LOG = LoggerFactory.getLogger( AsymmetricCrypto.class );

    private static final String ALGORITHM_NAME = "RSA";

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Set the public key used during encryption or decryption.
     * 
     * @param resourceName
     *            The name of a resource on the classpath containing the public key. <strong>Must</strong>
     *            be in the DER format.
     */
    public void setPublicKey( String resourceName ) {
        publicKey = loadPublicKey( resourceName );
    }

    /**
     * Set the public key used during encryption or decryption.
     * 
     * @param keyStream
     *            The input stream containing the public key. <strong>Must</strong> be in the DER
     *            format.
     */
    public void setPublicKey( InputStream keyStream ) {
        publicKey = loadPublicKey( keyStream );
    }
    
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Set the private key used during encryption or decryption.
     * 
     * @param resourceName
     *            The name of a resource on the classpath containing the private key. <strong>Must</strong>
     *            be in the DER format.
     */
    public void setPrivateKey( String resourceName ) {
        privateKey = loadPrivateKey( resourceName );
    }

    /**
     * Set the private key used during encryption or decryption.
     * 
     * @param keyStream
     *            The input stream containing the private key. <strong>Must</strong> be in the DER
     *            format.
     */
    public void setPrivateKey( InputStream keyStream ) {
        privateKey = loadPrivateKey( keyStream );
    }

    public byte[] encryptWithPublicKey( byte[] data )
            throws CryptoException {
        return crypt( data, publicKey, Cipher.ENCRYPT_MODE );
    }

    public byte[] encryptWithPrivateKey( byte[] data )
            throws CryptoException {
        return crypt( data, privateKey, Cipher.ENCRYPT_MODE );
    }

    public byte[] decryptWithPrivateKey( byte[] data )
            throws CryptoException {
        return crypt( data, privateKey, Cipher.DECRYPT_MODE );
    }

    public byte[] decryptWithPublicKey( byte[] data )
            throws CryptoException {
        return crypt( data, publicKey, Cipher.DECRYPT_MODE );
    }

    private byte[] crypt( byte[] data, Key key, int mode )
            throws CryptoException {
        byte[] result = null;

        try {
            Cipher aesCipher = Cipher.getInstance( ALGORITHM_NAME );
            // Initialize the Cipher for the required mode.
            aesCipher.init( mode, key );
            // Do the encryption/decryption.
            result = aesCipher.doFinal( data );
        } catch ( NoSuchAlgorithmException e ) {
            throw new CryptoException( e );
        } catch ( NoSuchPaddingException e ) {
            throw new CryptoException( e );
        } catch ( InvalidKeyException e ) {
            throw new CryptoException( e );
        } catch ( IllegalBlockSizeException e ) {
            throw new CryptoException( e );
        } catch ( BadPaddingException e ) {
            throw new CryptoException( e );
        }

        return result;
    }

    private static RSAPublicKey loadPublicKey( String resourceName ) {
        // Get the resource containing the public key.
        InputStream keyStream = AsymmetricCrypto.class.getResourceAsStream( resourceName );
        if ( keyStream == null ) {
            LOG.info( "Public key is missing." );
            return null;
        }
        return loadPublicKey( keyStream );
    }

    private static RSAPublicKey loadPublicKey( InputStream keyStream ) {
        RSAPublicKey pubKey = null;
        try {
            // Load the public key into the byte array.
            byte[] encKey = new byte[keyStream.available()];
            keyStream.read( encKey );
            keyStream.close();

            // Load the public key from the byte array into a PublicKey object.
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec( encKey );
            KeyFactory keyFactory = KeyFactory.getInstance( ALGORITHM_NAME );
            pubKey = (RSAPublicKey) keyFactory.generatePublic( pubKeySpec );
        } catch ( NoSuchAlgorithmException e ) {
            LOG.error( "Problem loading public key.", e );
        } catch ( InvalidKeySpecException e ) {
            LOG.error( "Problem loading public key.", e );
        } catch ( IOException e ) {
            LOG.error( "Problem loading public key.", e );
        }

        return pubKey;
    }

    private static RSAPrivateKey loadPrivateKey( String resourceName ) {
        // Get the resource containing the private key
        InputStream keyStream = AsymmetricCrypto.class.getResourceAsStream( resourceName );
        if ( keyStream == null ) {
            LOG.info( "Private key resource not available." );
            return null;
        }
        return loadPrivateKey( keyStream );
    }

    private static RSAPrivateKey loadPrivateKey( InputStream keyStream ) {
        RSAPrivateKey pubKey = null;
        try {
            // Load the private key into the byte array.
            byte[] encKey = new byte[keyStream.available()];
            keyStream.read( encKey );
            keyStream.close();

            // Load the private key from the byte array into a PrivateKey object.
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec( encKey );
            KeyFactory keyFactory = KeyFactory.getInstance( ALGORITHM_NAME );
            pubKey = (RSAPrivateKey) keyFactory.generatePrivate( privKeySpec );
        } catch ( NoSuchAlgorithmException e ) {
            LOG.error( "Problem loading private key.", e );
        } catch ( InvalidKeySpecException e ) {
            LOG.error( "Problem loading private key.", e );
        } catch ( IOException e ) {
            LOG.error( "Problem loading private key.", e );
        }
        return pubKey;
    }

}
