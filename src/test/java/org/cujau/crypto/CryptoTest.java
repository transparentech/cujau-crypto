package org.cujau.crypto;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.cujau.utils.Base64;
import org.cujau.utils.ResourceUtil;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoTest {

    private static final Logger LOG = LoggerFactory.getLogger( CryptoTest.class );
    
    private static final String PUBLIC_KEY_RESOURCE = "/public.der";
    private static final String PRIVATE_KEY_RESOURCE = "/private.der";

    private Crypto crypto;

    @Before
    public void before() {
        // System.setProperty( "java.security.egd", "file:/dev/urandom" );
        AsymmetricCrypto asymmetric = new AsymmetricCrypto();
        asymmetric.setPrivateKey( PRIVATE_KEY_RESOURCE );
        asymmetric.setPublicKey( PUBLIC_KEY_RESOURCE );
        crypto = new Crypto( asymmetric );
    }

    @Test
    public void testCrypto()
            throws CryptoException, IOException {
        String resStr = "abcdefghijklmnopqrstuvwxyz";
        doOneTest( resStr );
        
        resStr = ResourceUtil.getResourceAsString( "/testBigText.txt" );
        doOneTest( resStr );

        resStr = ResourceUtil.getResourceAsString( "/testXMLText.xml" );
        doOneTest( resStr );
    }
    
    @Test
    public void testCryptoWithBase64() throws CryptoException, IOException {
        String resStr = "abcdefghijklmnopqrstuvwxyz";
        doOneTestWithBase64( resStr );
        
        resStr = ResourceUtil.getResourceAsString( "/testBigText.txt" );
        doOneTestWithBase64( resStr );

        resStr = ResourceUtil.getResourceAsString( "/testXMLText.xml" );
        doOneTestWithBase64( resStr );
        
    }
    
    private void doOneTest( String resStr ) throws UnsupportedEncodingException, CryptoException {
        byte[] data = resStr.getBytes( "UTF-8" );
        byte[] encData = crypto.encrypt( data );
        byte[] data2 = crypto.decrypt( encData );
        assertTrue( data.length == data2.length );
        assertTrue( resStr.equals( new String( data2, "UTF-8" ) ) );
    }

    private void doOneTestWithBase64( String resStr ) throws UnsupportedEncodingException, CryptoException {
        byte[] data = resStr.getBytes( "UTF-8" );
        byte[] encData = crypto.encrypt( data );
        String encData64 = Base64.encodeBytes( encData );
        byte[] data2 = crypto.decrypt( Base64.decode( encData64 ) );
        assertTrue( data.length == data2.length );
        assertTrue( resStr.equals( new String( data2, "UTF-8" ) ) );
    }
}
