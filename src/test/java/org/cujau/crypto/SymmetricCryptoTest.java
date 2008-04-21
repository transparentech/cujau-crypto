package org.cujau.crypto;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.cujau.utils.Base64;
import org.cujau.utils.ResourceUtil;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SymmetricCryptoTest {

    private static final Logger LOG = LoggerFactory.getLogger( SymmetricCryptoTest.class );

    private SymmetricCrypto cry;

    @Before
    public void before() throws CryptoException {
        cry = new SymmetricCrypto();
    }

    @Test
    public void testRandomKey() {
        SecretKey key = cry.getRandomKey();
        assertNotNull( key );

        LOG.debug( "secret key={}", key.toString() );
        LOG.debug( "  encoded length = {}", key.getEncoded().length );
        LOG.debug( "  format = {}", key.getFormat() );

        assertTrue( key.getAlgorithm() == "AES" );
        assertTrue( key.getFormat() == "RAW" );
        assertTrue( key.getEncoded().length == 16 );

        // Test that they are random keys.
        String keyStr = Base64.encodeBytes( cry.getRandomKey().getEncoded() );
        assertFalse( keyStr.equals( Base64.encodeBytes( key.getEncoded() ) ) );
        assertFalse( keyStr.equals( Base64.encodeBytes( cry.getRandomKey().getEncoded() ) ) );
    }

    @Test
    public void testRandomIv()
            throws CryptoException {
        IvParameterSpec iv = cry.getRandomIV();
        assertNotNull( iv );

        String ivStr = Base64.encodeBytes( cry.getRandomIV().getIV() );
        assertFalse( ivStr.equals( Base64.encodeBytes( iv.getIV() ) ) );
        assertFalse( ivStr.equals( Base64.encodeBytes( cry.getRandomIV().getIV() ) ) );
    }

    @Test
    public void testSymmetricEncryptDecrypt()
            throws UnsupportedEncodingException, CryptoException {
        SecretKey key = cry.getRandomKey();
        assertNotNull( key );
        IvParameterSpec iv = cry.getRandomIV();
        assertNotNull( iv );

        String str = "abcdefghijklmnopqrstuvwxyz";
        byte[] strB = str.getBytes( "UTF-8" );
        assertTrue( strB.length == 26 );

        byte[] encStr = cry.encrypt( strB, key, iv );
        assertNotNull( encStr );
        assertTrue( encStr.length == 32 );

        byte[] deStr = cry.decrypt( encStr, key, iv );
        assertNotNull( deStr );
        assertTrue( deStr.length == 26 );

        String str2 = new String( deStr, "UTF-8" );
        assertTrue( str.equals( str2 ) );
    }

    @Test
    public void testSymmetricEncrypt()
            throws CryptoException, UnsupportedEncodingException {
        SecretKey key = cry.getRandomKey();
        IvParameterSpec iv = cry.getRandomIV();

        String str = "abcdefghijklmnopqrstuvwxyz";
        byte[] strB = str.getBytes( "UTF-8" );
        byte[] encStr = cry.encrypt( strB, key, iv );

        LOG.debug( "encStr='{}'", Base64.encodeBytes( encStr ) );
        LOG.debug( "key='{}'", Base64.encodeBytes( key.getEncoded() ) );
        LOG.debug( "iv='{}'", Base64.encodeBytes( iv.getIV() ) );
    }

    @Test
    public void testSymmetricDecrypt()
            throws CryptoException, UnsupportedEncodingException {
        String origStr = "abcdefghijklmnopqrstuvwxyz";

        // this was generated from the java code above.
        SecretKey key =
            new SecretKeySpec( Base64.decode( "YdBo7MahsuC0XDzpnYBgSA==" ), SymmetricCrypto.ALGORITHM_NAME );
        IvParameterSpec iv = new IvParameterSpec( Base64.decode( "X6rMYp4Fz472eRemJcojcA==" ) );
        byte[] encStr = Base64.decode( "fyzDta2O9SEpoyDMza4r6jAzc0v3FDLwx0M2HOwY9Cc=" );

        byte[] strB = cry.decrypt( encStr, key, iv );
        String str = new String( strB, "UTF-8" );
        assertTrue( origStr.equals( str ) );

        // this was generated from ruby.
        key =
            new SecretKeySpec( Base64.decode( "tPzm81tNV4DuIQfC6ZpsAQ==" ), SymmetricCrypto.ALGORITHM_NAME );
        iv = new IvParameterSpec( Base64.decode( "5M0fnVj86rA/r2pKbypjOA==" ) );
        encStr = Base64.decode( "hozAHHwsCkoNkzkP2EHDVzsCxr9S6SNQEcJn44hWxwg=" );

        strB = cry.decrypt( encStr, key, iv );
        str = new String( strB, "UTF-8" );
        assertTrue( origStr.equals( str ) );
    }
    
    @Test
    public void testBigEncryptDecrypt()
            throws IOException, CryptoException {
        String bigStr = ResourceUtil.getResourceAsString( "/testBigText.txt" );
        assertNotNull( bigStr );

        SecretKey key = cry.getRandomKey();
        assertNotNull( key );
        IvParameterSpec iv = cry.getRandomIV();
        assertNotNull( iv );

        byte[] strB = bigStr.getBytes( "UTF-8" );
        byte[] encStr = cry.encrypt( strB, key, iv );
        assertNotNull( encStr );
        byte[] deStr = cry.decrypt( encStr, key, iv );
        assertNotNull( deStr );

        String str2 = new String( deStr, "UTF-8" );
        assertTrue( bigStr.equals( str2 ) );
    }
}
