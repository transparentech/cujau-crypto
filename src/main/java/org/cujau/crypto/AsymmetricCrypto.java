package org.cujau.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
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

    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final int keySizeBytes;
    private final String algorithmName;

    /**
     * Create a new AssymmetricCrypto instance.
     * 
     * @param algorithm
     *            The name of the algorithm use to create the keys. Examples are 'RSA' and 'DSA'.
     * @param privateKeyResourceName
     *            The name of a resource on the classpath containing the private key. <strong>Must</strong>
     *            be in the DER format.
     * @param publicKeyResourceName
     *            The name of a resource on the classpath containing the public key. <strong>Must</strong>
     *            be in the DER format.
     */
    public AsymmetricCrypto( String algorithm, String privateKeyResourceName, String publicKeyResourceName ) {
        algorithmName = algorithm;
        publicKey = loadPublicKey( algorithmName, publicKeyResourceName );
        privateKey = loadPrivateKey( algorithmName, privateKeyResourceName );
        keySizeBytes = calculateKeySizeInBytes();
    }

    /**
     * Create a new AssymmetricCrypto instance.
     * 
     * @param algorithm
     *            The name of the algorithm use to create the keys. Examples are 'RSA' and 'DSA'.
     * @param privateKeyStream
     *            The input stream containing the private key. <strong>Must</strong> be in the DER
     *            format.
     * @param publicKeyStream
     *            The input stream containing the public key. <strong>Must</strong> be in the DER
     *            format.
     */
    public AsymmetricCrypto( String algorithm, InputStream privateKeyStream, InputStream publicKeyStream ) {
        algorithmName = algorithm;
        publicKey = loadPublicKey( algorithm, publicKeyStream );
        privateKey = loadPrivateKey( algorithm, privateKeyStream );
        keySizeBytes = calculateKeySizeInBytes();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Get the size of the keys in bytes. This value is also the length of any data encrypted with
     * the keys.
     * 
     * @return The size in bytes of the keys.
     */
    public int getKeySizeBytes() {
        return keySizeBytes;
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
            Cipher aesCipher = Cipher.getInstance( algorithmName );
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

    private static PublicKey loadPublicKey( String algorithmName, String resourceName ) {
        if ( resourceName == null ) {
            return null;
        }
        // Get the resource containing the public key.
        InputStream keyStream = AsymmetricCrypto.class.getResourceAsStream( resourceName );
        if ( keyStream == null ) {
            LOG.info( "Public key is missing." );
            return null;
        }
        return loadPublicKey( algorithmName, keyStream );
    }

    private static PublicKey loadPublicKey( String algorithmName, InputStream keyStream ) {
        if ( keyStream == null ) {
            return null;
        }
        PublicKey pubKey = null;
        try {
            // Load the public key into the byte array.
            byte[] encKey = new byte[keyStream.available()];
            keyStream.read( encKey );
            keyStream.close();

            // Load the public key from the byte array into a PublicKey object.
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec( encKey );
            KeyFactory keyFactory = KeyFactory.getInstance( algorithmName );
            pubKey = (PublicKey) keyFactory.generatePublic( pubKeySpec );
        } catch ( NoSuchAlgorithmException e ) {
            LOG.error( "Problem loading public key.", e );
        } catch ( InvalidKeySpecException e ) {
            LOG.error( "Problem loading public key.", e );
        } catch ( IOException e ) {
            LOG.error( "Problem loading public key.", e );
        }

        return pubKey;
    }

    private static PrivateKey loadPrivateKey( String algorithmName, String resourceName ) {
        if ( resourceName == null ) {
            return null;
        }
        // Get the resource containing the private key
        InputStream keyStream = AsymmetricCrypto.class.getResourceAsStream( resourceName );
        if ( keyStream == null ) {
            LOG.info( "Private key resource not available." );
            return null;
        }
        return loadPrivateKey( algorithmName, keyStream );
    }

    private static PrivateKey loadPrivateKey( String algorithmName, InputStream keyStream ) {
        if ( keyStream == null ) {
            return null;
        }
        PrivateKey pubKey = null;
        try {
            // Load the private key into the byte array.
            byte[] encKey = new byte[keyStream.available()];
            keyStream.read( encKey );
            keyStream.close();

            // Load the private key from the byte array into a PrivateKey object.
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec( encKey );
            KeyFactory keyFactory = KeyFactory.getInstance( algorithmName );
            pubKey = (PrivateKey) keyFactory.generatePrivate( privKeySpec );
        } catch ( NoSuchAlgorithmException e ) {
            LOG.error( "Problem loading private key.", e );
        } catch ( InvalidKeySpecException e ) {
            LOG.error( "Problem loading private key.", e );
        } catch ( IOException e ) {
            LOG.error( "Problem loading private key.", e );
        }
        return pubKey;
    }

    private int calculateKeySizeInBytes() {
        try {
            if ( publicKey != null ) {
                return crypt( "x".getBytes( "UTF-8" ), publicKey, Cipher.ENCRYPT_MODE ).length;
            } else if ( privateKey != null ) {
                return crypt( "x".getBytes( "UTF-8" ), privateKey, Cipher.ENCRYPT_MODE ).length;
            }
        } catch ( UnsupportedEncodingException e ) {
            // Ignore as this should never happen.
        } catch ( CryptoException e ) {
            // This probably won't happen.
            LOG.warn( "Problem encrypting 'x' to get key size in bytes!", e );
        }
        return 0;
    }
}
