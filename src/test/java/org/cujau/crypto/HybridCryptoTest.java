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

public class HybridCryptoTest {

    private static final Logger LOG = LoggerFactory.getLogger( HybridCryptoTest.class );
    
    private static final String PUBLIC_KEY_RESOURCE = "/public.der";
    private static final String PRIVATE_KEY_RESOURCE = "/private.der";

    private HybridCrypto hybrid;

    @Before
    public void before() {
        // System.setProperty( "java.security.egd", "file:/dev/urandom" );
        AsymmetricCrypto asymmetric = new AsymmetricCrypto();
        asymmetric.setPrivateKey( PRIVATE_KEY_RESOURCE );
        asymmetric.setPublicKey( PUBLIC_KEY_RESOURCE );
        hybrid = new HybridCrypto( asymmetric );
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
    
    @Test
    public void testHybridEncrypt() throws UnsupportedEncodingException, CryptoException {
        String resStr = "abcdefghijklmnopqrstuvwxyz";
        byte[] data = resStr.getBytes( "UTF-8" );
        byte[] encData = hybrid.encryptWithPrivateKey( data );
        LOG.debug( "encData='{}'", Base64.encodeBytes( encData ) );

        encData = hybrid.encryptWithPublicKey( data );
        LOG.debug( "encData='{}'", Base64.encodeBytes( encData ) );
    }
    
    @Test
    public void testHybridDecrypt() throws UnsupportedEncodingException, CryptoException {
        String str = "abcdefghijklmnopqrstuvwxyz";
        String resStr = "gIdA7QOpdCpG3QkmJmmyWbtsFK1ncZxXiN3yIjSjo80sIfO54lWrIuVt5XMW\nwWx24/oHt/Kc7voQdt+s/jZq9sM4Sye8+m4LWSX07c1yroR++TECKC5QObkO\nu3420EUGLJanjtWJN8E9kJ9Fes+9XGjGxSHmT4XhMGMe9a+1qK36LcR/oZw1\nn3RBf6ShVs4juCq8tfzono8QZC7dq6oM5wY6s7ezm46MoH3F4Gg9j1e4oiuC\nf+n2q9Nlo+A92LNQwLz+i3BFt34eIqyrqLFEL+iwqmabK86DL4iEvAxXw7xP\nd8DidFvHIahG63llYxSyGmtoJAagzG5e0HzQTD9gqJgiR812VGKlXRPBCQSJ\nAiXUCYIJ2fsKK3gCCxGnmAOEsYmXsLZSOk7prpfb+MOqMI59gMgR2iUJO0jg\nDVyEgXE5f/ASegZwU5tGLthNQDWshAnzyVC/T/A4wb83ZbH5EURBpx3gvRca\n+k0GrIJSpC4rYeOPEuhGOE91vqlBp02QiLosg4E3dqGVyah3A5nUP5DspRo+\nJIZp33/WiI48U3iElzup/fKkD3PG7pN1m0zP4Dkql8+axOsNK5wzJjoc+EFJ\nkElYoqdFRqJVhneCO1K016xepJX/Y9iih+N8ic+aAKnR4GHP3hfP7t+Ii/MB\nDDWVWCDUuk2ZjvM23GPIlamoqUUQ+/eUXQ4qJX0kjbMz+z8fPTYyiK8cP3jC\nQHTDyA==";
        assertTrue( str.equals( new String( hybrid.decryptWithPrivateKey( Base64.decode( resStr ) ), "UTF-8" ) ) );
        
        resStr = "BuwojihmSKfwGv8amXDzdDuEof/S56Oh106RSdv55nqkdzzFIpw+AMzWiEUZ\nh9hkJFV3l2ZioBvGGCahXXFZgcu+/7eYACRB+MWw2d4C7pH9lzmfBY/rgCGP\nshTRb50mJulF1UMK20TVNfQo0sdkdFGVCrT/OIlJFaUYdVC9L6m8o5BmbgGL\n+jIGU44k5llTqc3ml9dCGe7pOvkBHsG4RaAr3AeWgmtXqyMtg1osfgPZHLyt\nbFRn3uEugeBw9vlUvk18EeH2YMRhtj4NhhLTYQTTkGGQiWJa+llpUZQiA3Tb\nChRgIvaed1xLYyiTxwXlk23+ts+0Z1MQ28/YUMmPZhNrlBFgukhBItekOB6w\nVaIpI4bQbX4UKxdnguJjbxrTyBzwakTWlZR12oyD8R/i8dOTWBUgwSrqE47X\nTJUAocKLg8MLopGyLWy+C1p41xgDHHG7HQorqtaA3/7jLcyDLpiaLEJhxX7/\nvD0EFg8IqtA0IX3dhKdE5tiSOxQCx6zFiFQ16Yvs98qyB7shJhODAlI0ADgz\nnDhmamjOWZ/qMTMc0R82TzeHJ/TeTk5Gb1arX7vAuSIeV+++BKCjyBl1yRbV\nzl90X0R5Oojd2D1plbtl641sRmF7khHBPkl5ek/jnHvK4cDwZzDQmgv0PRmN\nb2ZY4ik/yTkuyoL4JpRWujj+/pNKiFz4aYzhN0dKI7egO+l1GpWTWZgT/kNL\nkyeueg==";
        assertTrue( str.equals( new String( hybrid.decryptWithPublicKey( Base64.decode( resStr ) ), "UTF-8" ) ) );
    }
    
    private void doOneTest( String resStr ) throws UnsupportedEncodingException, CryptoException {
        byte[] data = resStr.getBytes( "UTF-8" );
        byte[] encData = hybrid.encryptWithPrivateKey( data );
        byte[] data2 = hybrid.decryptWithPublicKey( encData );
        assertTrue( data.length == data2.length );
        assertTrue( resStr.equals( new String( data2, "UTF-8" ) ) );
        
        encData = hybrid.encryptWithPublicKey( data );
        data2 = hybrid.decryptWithPrivateKey( encData );
        assertTrue( data.length == data2.length );
        assertTrue( resStr.equals( new String( data2, "UTF-8" ) ) );
    }

    private void doOneTestWithBase64( String resStr ) throws UnsupportedEncodingException, CryptoException {
        byte[] data = resStr.getBytes( "UTF-8" );
        byte[] encData = hybrid.encryptWithPrivateKey( data );
        String encData64 = Base64.encodeBytes( encData );
        byte[] data2 = hybrid.decryptWithPublicKey( Base64.decode( encData64 ) );
        assertTrue( data.length == data2.length );
        assertTrue( resStr.equals( new String( data2, "UTF-8" ) ) );
        
        encData = hybrid.encryptWithPublicKey( data );
        encData64 = Base64.encodeBytes( encData );
        data2 = hybrid.decryptWithPrivateKey( Base64.decode( encData64 ) );
        assertTrue( data.length == data2.length );
        assertTrue( resStr.equals( new String( data2, "UTF-8" ) ) );

    }
}
