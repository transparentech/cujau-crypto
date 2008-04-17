package org.cujau.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TwoTest implements Serializable {
    private static final Logger LOG = LoggerFactory.getLogger( TwoTest.class );
    private static final String INPUT =
        "This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.";
    private static final String PUBLIC_KEY_RESOURCE = "/public.der";
    private static final String PRIVATE_KEY_RESOURCE = "/private.der";
    
    public static PublicKey getPublicKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        InputStream keyfis = TwoTest.class.getResourceAsStream( PUBLIC_KEY_RESOURCE );
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read( encKey );
        keyfis.close();
        
        LOG.debug( new String( encKey ) );
//        PKCS8EncodedKeySpec bobPubKeySpec = new PKCS8EncodedKeySpec( encKey );
//        RSAPublicKeySpec bobPubKeySpec = new RSAPublicKeySpec( encKey );
      X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec( encKey );
        KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
        PublicKey bobPubKey = (RSAPublicKey) keyFactory.generatePublic( bobPubKeySpec );
        return bobPubKey;
    }

    public static PrivateKey getprivateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        InputStream keyfis = TwoTest.class.getResourceAsStream( PRIVATE_KEY_RESOURCE );
        byte[] encKey = new byte[keyfis.available()];
        keyfis.read( encKey );
        keyfis.close();
        
        LOG.debug( new String( encKey ) );
//        KeySpec spec = new PKCS8EncodedKeySpec( encKey );
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( encKey );
//        RSAPublicKeySpec bobPubKeySpec = new RSAPublicKeySpec( encKey );
//      X509EncodedKeySpec spec = new X509EncodedKeySpec( encKey );
        KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );
        PrivateKey bobPubKey = (RSAPrivateKey) keyFactory.generatePrivate( spec );
        return bobPubKey;
    }

    public static void encrypt()
            throws Exception {
        SecretKey secretKey = getDesKey();

        // create a random IV
        byte[] iv = new byte[8];
        SecureRandom sr = SecureRandom.getInstance( "SHA1PRNG" );
        sr.nextBytes( iv );
        IvParameterSpec ivSpec = new IvParameterSpec( iv );

        Cipher cipher = Cipher.getInstance( "DES/CBC/PKCS5Padding" );
        cipher.init( Cipher.ENCRYPT_MODE, secretKey, ivSpec );

        // write IV to file BEFORE enabling the cipherstream
        FileOutputStream fos = new FileOutputStream( "Z:/myfile.dat" );
        BufferedOutputStream bos = new BufferedOutputStream( fos );
        bos.write( iv );
        bos.flush();

        CipherOutputStream cos = new CipherOutputStream( bos, cipher );
        ObjectOutputStream oos = new ObjectOutputStream( cos );

        List<String> stringsToEncrypt = new ArrayList<String>();
        stringsToEncrypt.add( "testing" );
        stringsToEncrypt.add( "1" );
        stringsToEncrypt.add( "2" );
        stringsToEncrypt.add( "3" );

        for ( String s : stringsToEncrypt ) {
            oos.writeUTF( s );
        }
        oos.close();
    }

    public static void decrypt()
            throws Exception {
        SecretKey secretKey = getDesKey();

        // fetch the iv from the file
        FileInputStream fis = new FileInputStream( "Z:/myfile.dat" );
        BufferedInputStream bis = new BufferedInputStream( fis );
        byte[] iv = new byte[8];
        bis.read( iv, 0, 8 );
        IvParameterSpec ivSpec = new IvParameterSpec( iv );

        Cipher cipher = Cipher.getInstance( "DES/CBC/PKCS5Padding" );
        cipher.init( Cipher.DECRYPT_MODE, secretKey, ivSpec );

        CipherInputStream cis = new CipherInputStream( bis, cipher );
        ObjectInputStream ois = new ObjectInputStream( cis );

        List<String> decryptedStrings = new ArrayList<String>();

        try {
            while ( true ) {
                decryptedStrings.add( ois.readUTF() );
            }
        } catch ( EOFException ex ) {
            // done reading...
        }

        System.out.println( "Contents of decrypted file:" );
        for ( String s : decryptedStrings ) {
            System.out.println( s );
        }
    }

    public static SecretKey getDesKey()
            throws Exception {
        String setJCEKey = "12345678";
        byte[] key = setJCEKey.getBytes();
        DESKeySpec desKeySpec = new DESKeySpec( key );
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance( "DES" );
        return keyFactory.generateSecret( desKeySpec );
    }

    @Test
    public void main()
            throws Exception {
        LOG.debug( TwoTest.getPublicKey().toString() );
        LOG.debug( TwoTest.getprivateKey().toString() );
//        TwoTest.encrypt();
//        TwoTest.decrypt();
    }

}
