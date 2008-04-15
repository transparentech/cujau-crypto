package org.example.code.encryption;

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

    private static final String PUBLIC_KEY_RESOURCE = "/public.der";
    private static final String PRIVATE_KEY_RESOURCE = "/private.der";
//    private static final String ALGORITHM_NAME = "RSA/ECB/PKCS1Padding";
    private static final String ALGORITHM_NAME = "RSA";

    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    public AsymmetricCrypto() {
        publicKey = loadPublicKey( PUBLIC_KEY_RESOURCE );
        privateKey = loadPrivateKey( PRIVATE_KEY_RESOURCE );
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public byte[] encryptWithPublicKey( byte[] data ) throws CryptoException {
        return crypt( data, publicKey, Cipher.ENCRYPT_MODE );
    }

    public byte[] encryptWithPrivateKey( byte[] data ) throws CryptoException {
        return crypt( data, privateKey, Cipher.ENCRYPT_MODE );
    }

    public byte[] decryptWithPrivateKey( byte[] data ) throws CryptoException {
        return crypt( data, privateKey, Cipher.DECRYPT_MODE );
    }
    
    public byte[] decryptWithPublicKey( byte[] data ) throws CryptoException {
        return crypt( data, publicKey, Cipher.DECRYPT_MODE );
    }
    
    private byte[] crypt( byte[] data, Key key, int mode ) throws CryptoException {
        byte[] result = null;
        
        try {
            Cipher aesCipher = Cipher.getInstance( ALGORITHM_NAME );

            /*
             * Step 3. Initialize the Cipher for Encryption
             */
            aesCipher.init( mode, key );

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
        } catch ( IllegalBlockSizeException e ) {
            throw new CryptoException( e );            
        } catch ( BadPaddingException e ) {
            throw new CryptoException( e );            
        }
        
        return result;
    }
    
    private static RSAPublicKey loadPublicKey( String resourceName ) {
        RSAPublicKey pubKey = null;
        try {
            // Get the resource containing the public key.
            InputStream keyResource = TwoTest.class.getResourceAsStream( resourceName );
            if ( keyResource == null ) {
                LOG.info( "Public key is missing." );
                return null;
            }
            // Load the public key into the byte array.
            byte[] encKey = new byte[keyResource.available()];
            keyResource.read( encKey );
            keyResource.close();

            // PKCS8EncodedKeySpec bobPubKeySpec = new PKCS8EncodedKeySpec( encKey );
            // RSAPublicKeySpec bobPubKeySpec = new RSAPublicKeySpec( encKey );
            // Load the public key from the byte array into a PublicKey object.
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec( encKey );
            KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
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
        RSAPrivateKey pubKey = null;
        try {
            // Get the resource containing the private key
            InputStream keyResource = TwoTest.class.getResourceAsStream( resourceName );
            if ( keyResource == null ) {
                LOG.info( "Private key is mssing." );
                return null;
            }
            // Load the private key into the byte array.
            byte[] encKey = new byte[keyResource.available()];
            keyResource.read( encKey );
            keyResource.close();

            // KeySpec spec = new PKCS8EncodedKeySpec( encKey );
            // RSAPublicKeySpec bobPubKeySpec = new RSAPublicKeySpec( encKey );
            // X509EncodedKeySpec spec = new X509EncodedKeySpec( encKey );
            // Load the private key from the byte array into a PrivateKey object.
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec( encKey );
            KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
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
