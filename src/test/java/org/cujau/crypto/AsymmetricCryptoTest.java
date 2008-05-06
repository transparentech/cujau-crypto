package org.cujau.crypto;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.cujau.utils.Base64;
import org.cujau.utils.ResourceUtil;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AsymmetricCryptoTest {
    
    private static final Logger LOG = LoggerFactory.getLogger( AsymmetricCryptoTest.class );

    private static final String CERTSTORE_RESOURCE = "/cujauCertStore.jks";
    private static final String CERTSTORE_PASSWORD = "changeit";
    private static final String CERTSTORE_ALIAS = "cujau";

    private static final String KEYSTORE_RESOURCE = "/cujauKeyStore.jks";
    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEYSTORE_ALIAS = "cujau";
    private static final String KEYSTORE_ALIAS_PASSWORD = "changeit";

    private AsymmetricCrypto cry;

    @Before
    public void before() {
        cry = new AsymmetricCrypto();

        InputStream certStream = getClass().getResourceAsStream( CERTSTORE_RESOURCE );
        PublicKey pub = AsymmetricCrypto.loadPublicKey( certStream, CERTSTORE_PASSWORD, CERTSTORE_ALIAS );
        cry.setPublicKey( pub );

        InputStream keyStream = getClass().getResourceAsStream( KEYSTORE_RESOURCE );
        PrivateKey priv =
            AsymmetricCrypto.loadPrivateKey( keyStream, KEYSTORE_PASSWORD, KEYSTORE_ALIAS,
                                             KEYSTORE_ALIAS_PASSWORD );
        cry.setPrivateKey( priv );
    }

    @Test
    public void testPublicKey() {
        PublicKey key = cry.getPublicKey();
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
        PrivateKey key = cry.getPrivateKey();
        assertNotNull( key );

        LOG.debug( "private key={}", key.toString() );
        LOG.debug( "  encoded length = {}", key.getEncoded().length );
        LOG.debug( "  format = {}", key.getFormat() );

        assertTrue( key.getAlgorithm() == "RSA" );
        assertTrue( key.getFormat() == "PKCS#8" );
        assertTrue( key.getEncoded().length == 1217 );
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

        String strEnc = "lF6SkiCIpvQE/TgA0BKx9zcv8lvh8BBoK0j8OYK7x0fp4hRFFoPN3z8v5Jve\nMEpeAB4mEQ4GH6+YBUNmCbZU+997rxxMcQCqROKu6oeLnn4MWbkZ4lABPLX9\nt1hvlJLR29MR0JtwK3MwR0qIZeF/vWrqZ3ks6NVr/ntqRntXaNnjXNiYwr9y\n9P40Up57ZR8B13P2D9W63BsnLfdSk8wjTPuj5JCwwNW8DW/N7CEZaMyydwP1\nGuI5rR/0ul7DhNn2oav7LI2Y4B94tv/bPTLTIXCM5Pzh2ZCpxj1sqmkwKF1h\n9Ebc0cXMcMUkybyGuxOOVW/fKXd/Y0vkoGMBV7NkVg==";
        byte[] encStr = cry.decryptWithPrivateKey( Base64.decode( strEnc ) );
        String strNew = new String( encStr, "UTF-8" );
        assertTrue( str.equals( strNew ) );

        strEnc = "VFdb/fg3TtWq0T6Agw9dbsigs3WG4xUjpHEDWnJIbT4YxCTiPaA+BGkt6HBd\nSfKutjElgXgvxuUnL4xHbCeD9CpMQYOktVVaQA227KBjv/OUTmrwr8qJhj35\n8RWuOtJAmvTHGSiVm5oXNbIpf7raJ+rnD71xnMVbNTEzNonazUjIlgDzasR8\nDLzFsQ+vpChmnGxrfJUens8aQ7rg09SgQBQprttt8jFRJbIoqV5sYB7E9wTH\nd6Wh6yc3kkdm4TK/un/nARqCwkFSP8czbAo5VFVbeyQXjkyYBDx+Aw1r2kMA\n7gBBTbGW9DyHdA3SyflIxqHgMlT/qOgU+DKfTYGdgg==";
        encStr = cry.decryptWithPublicKey( Base64.decode( strEnc ) );
        strNew = new String( encStr, "UTF-8" );
        assertTrue( str.equals( strNew ) );
    }

    @Test
    public void testBigEncryptDecrypt()
            throws IOException {
        String bigStr = ResourceUtil.getResourceAsString( "/testBigText.txt" );
        assertNotNull( bigStr );

        byte[] encStr = null;
        try {
            encStr = cry.encryptWithPublicKey( bigStr.getBytes( "UTF-8" ) );
        } catch ( CryptoException e ) {
            assertTrue( true );
        }
        assertNull( encStr );
    }
}
