package org.example.code.crypto;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.example.code.crypto.AsymmetricCrypto;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AsymmetricCryptoTest {
    private static final Logger LOG = LoggerFactory.getLogger( AsymmetricCryptoTest.class );
    
    private AsymmetricCrypto cry;
    
    @Before
    public void before() {
        cry = new AsymmetricCrypto();
    }
    
    @Test
    public void testPublicKey() {
        RSAPublicKey key = cry.getPublicKey();
        assertNotNull( key );
        
        LOG.debug( "public key={}", key.toString() );
        LOG.debug( "  encoded length = {}", key.getEncoded().length );
        LOG.debug( "  format = {}", key.getFormat() );
        
        assertTrue( key.getAlgorithm() == "RSA" );
        assertTrue( key.getFormat() == "X.509" );
        assertTrue( key.getEncoded().length == 294 );
    }

    @Test
    public void testPrivateKey() {
        RSAPrivateKey key = cry.getPrivateKey();
        assertNotNull( key );
        
        LOG.debug( "private key={}", key.toString() );
        LOG.debug( "  encoded length = {}", key.getEncoded().length );
        LOG.debug( "  format = {}", key.getFormat() );
        
        assertTrue( key.getAlgorithm() == "RSA" );
        assertTrue( key.getFormat() == "PKCS#8" );
        assertTrue( key.getEncoded().length == 1218 );
    }
    
    @Test
    public void testPublicEncryptPrivateDecrypt() throws UnsupportedEncodingException, CryptoException {
        String str = "abcdefghijklmnopqrstuvwxyz";
        byte[] strB = str.getBytes( "UTF-8" );
        assertTrue( strB.length == 26 );

        byte[] encStr = cry.encryptWithPublicKey( strB );
        assertNotNull( encStr );
        assertTrue( encStr.length == 256 );

        byte[] deStr = cry.decryptWithPrivateKey( encStr );
        assertNotNull( deStr );
        assertTrue( deStr.length == 26 );

        String str2 = new String( deStr, "UTF-8" );
        assertTrue( str.equals( str2 ) );
    }

    @Test
    public void testPrivateEncryptPublicDecrypt() throws UnsupportedEncodingException, CryptoException {
        String str = "abcdefghijklmnopqrstuvwxyz";
        byte[] strB = str.getBytes( "UTF-8" );
        assertTrue( strB.length == 26 );

        byte[] encStr = cry.encryptWithPrivateKey( strB );
        assertNotNull( encStr );
        assertTrue( encStr.length == 256 );

        byte[] deStr = cry.decryptWithPublicKey( encStr );
        assertNotNull( deStr );
        assertTrue( deStr.length == 26 );

        String str2 = new String( deStr, "UTF-8" );
        assertTrue( str.equals( str2 ) );
    }

    @Test
    public void testPrivateEncryptPrivateDecrypt() throws UnsupportedEncodingException, CryptoException {
        String str = "abcdefghijklmnopqrstuvwxyz";
        byte[] strB = str.getBytes( "UTF-8" );
        assertTrue( strB.length == 26 );

        
        byte[] encStr = cry.encryptWithPrivateKey( strB );
        assertNotNull( encStr );
        assertTrue( encStr.length == 256 );

        byte[] deStr = null;
        try {
            deStr = cry.decryptWithPrivateKey( encStr );
        } catch ( CryptoException e ) {
            LOG.debug( e.getMessage() );
            assertTrue( true );
        }
        assertNull( deStr );
    }

    @Test
    public void testPublicEncryptPublicDecrypt() throws UnsupportedEncodingException, CryptoException {
        String str = "abcdefghijklmnopqrstuvwxyz";
        byte[] strB = str.getBytes( "UTF-8" );
        assertTrue( strB.length == 26 );
        
        byte[] encStr = cry.encryptWithPublicKey( strB );
        assertNotNull( encStr );
        assertTrue( encStr.length == 256 );

        byte[] deStr = null;
        try {
            deStr = cry.decryptWithPublicKey( encStr );
        } catch ( CryptoException e ) {
            LOG.debug( e.getMessage() );
            assertTrue( true );
        }
        assertNull( deStr );
    }
}
