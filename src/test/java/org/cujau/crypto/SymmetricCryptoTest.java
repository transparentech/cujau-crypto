package org.cujau.crypto;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;

import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SymmetricCryptoTest {

    private static final Logger LOG = LoggerFactory.getLogger( SymmetricCryptoTest.class );

    private SymmetricCrypto cry;

    @Before
    public void before() {
        cry = new SymmetricCrypto();
    }

    @Test
    public void testSecretKey() {
        SecretKey key = cry.getAESSecret();
        assertNotNull( key );

        LOG.debug( "secret key={}", key.toString() );
        LOG.debug( "  encoded length = {}", key.getEncoded().length );
        LOG.debug( "  format = {}", key.getFormat() );

        assertTrue( key.getAlgorithm() == "AES" );
        assertTrue( key.getFormat() == "RAW" );
        assertTrue( key.getEncoded().length == 16 );
    }

    @Test
    public void testSymmetricEncryptDecrypt()
            throws UnsupportedEncodingException, CryptoException {
        SecretKey key = cry.getAESSecret();
        assertNotNull( key );

        String str = "abcdefghijklmnopqrstuvwxyz";
        byte[] strB = str.getBytes( "UTF-8" );
        assertTrue( strB.length == 26 );
        
        byte[] encStr = cry.encrypt( strB, key );
        assertNotNull( encStr );
        assertTrue( encStr.length == 32 );

        byte[] deStr = cry.decrypt( encStr, key );
        assertNotNull( deStr );
        assertTrue( deStr.length == 26 );

        String str2 = new String( deStr, "UTF-8" );
        assertTrue( str.equals( str2 ) );
    }

}
