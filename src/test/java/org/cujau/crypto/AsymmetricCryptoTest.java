package org.cujau.crypto;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.cujau.utils.Base64;
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
    public void testPublicEncryptPrivateDecrypt()
            throws UnsupportedEncodingException, CryptoException {
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
    public void testPrivateEncryptPublicDecrypt()
            throws UnsupportedEncodingException, CryptoException {
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
    public void testPrivateEncryptPrivateDecrypt()
            throws UnsupportedEncodingException, CryptoException {
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
    public void testPublicEncryptPublicDecrypt()
            throws UnsupportedEncodingException, CryptoException {
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

    @Test
    public void testAsymmetricEncrypt()
            throws UnsupportedEncodingException, CryptoException {
        String str = "abcdefghijklmnopqrstuvwxyz";
        byte[] strB = str.getBytes( "UTF-8" );
        assertTrue( strB.length == 26 );

        byte[] encStr = cry.encryptWithPublicKey( strB );
        assertNotNull( encStr );
        LOG.debug( "pubEnc='{}'", Base64.encodeBytes( encStr ) );

        encStr = cry.encryptWithPrivateKey( strB );
        assertNotNull( encStr );
        LOG.debug( "privEnc='{}'", Base64.encodeBytes( encStr ) );
    }

    @Test
    public void testAsymmetricDecrypt()
            throws UnsupportedEncodingException, CryptoException {
        String str = "abcdefghijklmnopqrstuvwxyz";

        String strEnc =
            "inReYMpD3A8v4mZZwWUsG9fDcAkJcf0nZfaGyBy0dnV/xknvyEYq5SWWVk4w\n9G/bB0bwWIdwzHqEKoNrJhqcC75xhRL8hXdCD5oAdvKCWt56fbcsr6/UIUky\nNERcGHicFNaLJx6jd/AV4f0jvH923OUq1XUiA+cQ/H4uUi+zx/2cwOTYIHI6\nWKCB6UWxJvvQCB7KDFtWI03H6Jdo/CRQVwyYpujEG3zls9C+4FpDgFZLIvLT\nfa1FiJjPEix6Usv+1pXrog7lwDw9b0R7oV60PgSzLNoCdyC2zOUPTKC4Gma1\nb8+Sz8tevZ5Qsc3AmidksM8qoitJH/o1VHMmj6iT4Q==";
        byte[] encStr = cry.decryptWithPrivateKey( Base64.decode( strEnc ) );
        String strNew = new String( encStr, "UTF-8" );
        assertTrue( str.equals( strNew ) );
        
        strEnc = "VA0AZe+dnKGpKWogySE/2lLTybc0hefEr+6WjVWWyTexDhM9xcWzffA7HvuJ\niKZzLbhtRkXu7x7vn2BpNc/FFeCMD0BpBzh6LRiKGgs3jdXtqcvoSMteFDQO\nJ6z3t7rpkuoJcjbHQTffXh0uXKYHzDUWX7uxkeL/z+y5tg49KnrDZhIWWwr1\n1emgIRla4/+43DUmwKNEzwBtlMMVASNU79tikLFKLwuSYsWCKonWWxkEWHbs\ngdDnww7oXQjt1+WajT2dI/cpkY6l0uVOMhLqX9NXKrhLM7KNL6qBAlgM3Erw\nfMd7xNvnXbO6JXvCAmA40nenycd5kSAvSuN9BUmffg==";
        encStr = cry.decryptWithPublicKey( Base64.decode( strEnc ) );
        strNew = new String( encStr, "UTF-8" );
        assertTrue( str.equals( strNew ) );
    }
}
