package org.cujau.crypto;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Asymmetric (public key) encryption.
 * 
 */
public class AsymmetricCrypto {

    private static final Logger LOG = LoggerFactory.getLogger( AsymmetricCrypto.class );

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private int keySizeBytes;

    /**
     * Default public constructor.
     * <p>
     * The public and private keys should be set using the {@link #setPrivateKey} and
     * {@link #setPublicKey} methods in conjunction with one of the
     * {@link #loadPrivateKey(KeyStore, String, String)} or {@link #loadPublicKey(KeyStore, String)}
     * methods.
     */
    public AsymmetricCrypto() {
    // Do nothing.
    }

    /**
     * Create a new AssymmetricCrypto instance.
     * <p>
     * More flexibility can be achieved using the {@link #AsymmetricCrypto() default constructor}.
     * 
     * @param keystore
     *            The keystore containing the private key. Can be <tt>null</tt>.
     * @param certstore
     *            The keystore containing the public key. Can be <tt>null</tt>.
     * @param alias
     *            The alias of the public key in the <tt>certstore</tt> and the private key in the
     *            <tt>keystore</tt>.
     * @param aliasPassword
     *            The password for accessing the private key alias in the <tt>keystore</tt>.
     */
    public AsymmetricCrypto( KeyStore keystore, KeyStore certstore, String alias, String aliasPassword ) {
        publicKey = loadPublicKey( certstore, alias );
        privateKey = loadPrivateKey( keystore, alias, aliasPassword );
        keySizeBytes = calculateKeySizeInBytes();
    }

    /**
     * Create a new AssymmetricCrypto instance.
     * <p>
     * More flexibility can be achieved using the {@link #AsymmetricCrypto() default constructor}.
     * 
     * @param keystoreStream
     *            The input stream of the keystore that contains the private key. Can be
     *            <tt>null</tt>.
     * @param certstoreStream
     *            The input stream of the keystore that contains the public key. Can be
     *            <tt>null</tt>.
     * @param storePassword
     *            The password required to load and access keys from the keystore and certstore.
     * @param alias
     *            The alias of the public key in the <tt>certstore</tt> and the private key in the
     *            <tt>keystore</tt>.
     * @param aliasPassword
     *            The password for accessing the private key alias in the <tt>keystore</tt>.
     */
    public AsymmetricCrypto( InputStream keystoreStream, InputStream certstoreStream, String storePassword,
                             String alias, String aliasPassword ) {
        publicKey = loadPublicKey( certstoreStream, storePassword, alias );
        privateKey = loadPrivateKey( keystoreStream, storePassword, alias, aliasPassword );
        keySizeBytes = calculateKeySizeInBytes();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey( PublicKey key ) {
        publicKey = key;
        keySizeBytes = calculateKeySizeInBytes();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey( PrivateKey key ) {
        privateKey = key;
        keySizeBytes = calculateKeySizeInBytes();
    }

    /**
     * Get the size of the keys in bytes. This value is also the length of any data encrypted with
     * the keys.
     * <p>
     * Note that this value is calculated from the public key first and if the public key is not
     * available then from the private key.
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

    /**
     * Using the keystore in the given <tt>InputStream</tt>, load and return the aliased public
     * key.
     * 
     * @param keystoreStream
     * @param keystorePassword
     * @param alias
     * @return
     */
    public static PublicKey loadPublicKey( InputStream keystoreStream, String keystorePassword, String alias ) {
        if ( keystoreStream == null ) {
            return null;
        }
        return loadPublicKey( getKeyStore( keystoreStream, keystorePassword ), alias );
    }

    /**
     * Using the given keystore, load and return the aliased public key.
     * 
     * @param keystore
     * @param alias
     * @return
     */
    public static PublicKey loadPublicKey( KeyStore keystore, String alias ) {
        if ( keystore == null ) {
            return null;
        }
        PublicKey pubKey = null;
        try {
            java.security.cert.Certificate cert = keystore.getCertificate( alias );
            return cert.getPublicKey();
        } catch ( KeyStoreException e ) {
            LOG.error( "Problem loading public key.", e );
        }

        return pubKey;
    }

    /**
     * Using the keystore in the given <tt>InputStream</tt>, load and return the aliased private
     * key.
     * 
     * @param keystoreStream
     * @param keystorePassword
     * @param alias
     * @param aliasPassword
     * @return
     */
    public static PrivateKey loadPrivateKey( InputStream keystoreStream, String keystorePassword, String alias,
                                      String aliasPassword ) {
        if ( keystoreStream == null ) {
            return null;
        }
        return loadPrivateKey( getKeyStore( keystoreStream, keystorePassword ), alias, aliasPassword );
    }

    /**
     * Using the given keystore, load and return the aliased private key.
     * 
     * @param keystore
     * @param alias
     * @param aliasPassword
     * @return
     */
    public static PrivateKey loadPrivateKey( KeyStore keystore, String alias, String aliasPassword ) {
        if ( keystore == null ) {
            return null;
        }
        PrivateKey pubKey = null;
        try {
            PrivateKey privKey = (PrivateKey) keystore.getKey( alias, aliasPassword.toCharArray() );
            return privKey;
        } catch ( UnrecoverableKeyException e ) {
            LOG.error( "Problem loading private key.", e );
        } catch ( KeyStoreException e ) {
            LOG.error( "Problem loading private key.", e );
        } catch ( NoSuchAlgorithmException e ) {
            LOG.error( "Problem loading private key.", e );
        }
        return pubKey;
    }

    public static KeyStore getKeyStore( InputStream keystoreStream, String keystorePassword ) {
        DataInputStream is = new DataInputStream( keystoreStream );
        try {
            KeyStore keystore = KeyStore.getInstance( "jks" );
            keystore.load( is, keystorePassword.toCharArray() );
            return keystore;
        } catch ( KeyStoreException e ) {
            LOG.error( "Problem loading keystore.", e );
        } catch ( NoSuchAlgorithmException e ) {
            LOG.error( "Problem loading keystore.", e );
        } catch ( CertificateException e ) {
            LOG.error( "Problem loading keystore.", e );
        } catch ( IOException e ) {
            LOG.error( "Problem loading keystore.", e );
        }
        return null;
    }

    private byte[] crypt( byte[] data, Key key, int mode )
            throws CryptoException {
        byte[] result = null;

        try {
            Cipher aesCipher = Cipher.getInstance( key.getAlgorithm() );
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
