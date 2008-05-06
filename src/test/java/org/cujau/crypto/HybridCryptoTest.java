package org.cujau.crypto;

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

public class HybridCryptoTest {

    private static final Logger LOG = LoggerFactory.getLogger( HybridCryptoTest.class );

    private static final String CERTSTORE_RESOURCE = "/cujauCertStore.jks";
    private static final String CERTSTORE_PASSWORD = "changeit";
    private static final String CERTSTORE_ALIAS = "cujau";

    private static final String KEYSTORE_RESOURCE = "/cujauKeyStore.jks";
    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEYSTORE_ALIAS = "cujau";
    private static final String KEYSTORE_ALIAS_PASSWORD = "changeit";

    private HybridCrypto hybrid;

    @Before
    public void before() {
        AsymmetricCrypto asymmetric = new AsymmetricCrypto();

        InputStream certStream = getClass().getResourceAsStream( CERTSTORE_RESOURCE );
        PublicKey pub = AsymmetricCrypto.loadPublicKey( certStream, CERTSTORE_PASSWORD, CERTSTORE_ALIAS );
        asymmetric.setPublicKey( pub );

        InputStream keyStream = getClass().getResourceAsStream( KEYSTORE_RESOURCE );
        PrivateKey priv =
            AsymmetricCrypto.loadPrivateKey( keyStream, KEYSTORE_PASSWORD, KEYSTORE_ALIAS,
                                             KEYSTORE_ALIAS_PASSWORD );
        asymmetric.setPrivateKey( priv );

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
    public void testCryptoWithBase64()
            throws CryptoException, IOException {
        String resStr = "abcdefghijklmnopqrstuvwxyz";
        doOneTestWithBase64( resStr );

        resStr = ResourceUtil.getResourceAsString( "/testBigText.txt" );
        doOneTestWithBase64( resStr );

        resStr = ResourceUtil.getResourceAsString( "/testXMLText.xml" );
        doOneTestWithBase64( resStr );

    }

    @Test
    public void testHybridEncrypt()
            throws UnsupportedEncodingException, CryptoException {
        String resStr = "abcdefghijklmnopqrstuvwxyz";
        byte[] data = resStr.getBytes( "UTF-8" );
        byte[] encData = hybrid.encryptWithPrivateKey( data );
        LOG.debug( "encData='{}'", Base64.encodeBytes( encData ) );

        encData = hybrid.encryptWithPublicKey( data );
        LOG.debug( "encData='{}'", Base64.encodeBytes( encData ) );
    }

    @Test
    public void testHybridDecrypt()
            throws UnsupportedEncodingException, CryptoException {
        String str = "abcdefghijklmnopqrstuvwxyz";
        String resStr = "ELTVwF4H23HqVctgJZs00TOIqSFqPtETtQY9JueLIgUzgurccTQaBFRnK4VP\nOGKum5zLknYqHqpVUxQu4p2tVH7FcGGHfGqXRUtHWo92PsQKbeG7EBSqkj+p\nnBZeM/OotqiiZEVj9nsRQk2bYSjxHRvP9EC1zvtoGmNam9NU3ev+JymNg6Fv\ntkMIvvjc2Chl5oMxDgb7iHbS9T55PX8oh2GABMYVcgl1ayRnNYqnks4ox/te\nVn+WqOL/RyI7P0PdbwF/b+EU4xLLKrxoz/gImdIpKEcJP5q66t3OlsGoFQGZ\nwsLrY2SMUJqjS/Tk3LeiiUsLDGtF9ALq4sUA80hsVyev1qVwFGyt0HPBsAKM\n9cl41cXR3mtPCNZWCbkVTKETVYObW6Sc4GTicE0/LBV0SyT3E96dtSCZ6buY\n2wbLGC03vXZHXuEu9PLB+aYe01sJMryKH2rp71C0AJhjbpdVdQT6I37ROS5c\neH+ShAPupqJlGLQEOzUbiQq7l9N0hP8OhzMFm7CZ1zrPgULzXDAq9cKWyg6g\nZVLnxnQrT19q9N/lBkxuIt1reO91pa6oYqPBpaH1V9zrojpou+vzeFSd5Rqb\ncILoEQTxcmWChNbiUbERAeV1QT/QIK5TWSXZ+6R1nR18Y+lSjdFIgn66x3n8\n3ENVDUUqvQ+fIHiYGkHykHVmSNGOcvNn5xdU2YgiW0qV3PB5VIHzHVv00Fx3\nXgJM4A==";
        assertTrue( str.equals( new String( hybrid.decryptWithPrivateKey( Base64.decode( resStr ) ), "UTF-8" ) ) );

        resStr = "V847XajP3IWARf6Q8lPPC/y9+NyJH7GUOu9/T/8mmtRcM4sWLehrEkiHx+tk\nlkmUrIQOfpCsAx2iLJvOuJA8ArPqPx+P/21rvuW47H8Q7FlHK3CfiIhUiKD7\n6HUwfQawSUxtSUSEW9kgpssDgS0rsdlSREjhefe8FtRvWVrRh8H92flChOCx\ndfrdrjqug7diZShrTOdkdpavVFi+yefh0FWA9I+aUf3I0LxGEAmeITylGghI\niSHWAUGNQ9sA6It5CIO+bRcoK4bGjaCjTKpmKSZ3KlDCBF2eEEV1X3vX03x0\nLe0u+1HXPko77TAa72rbl126Cc2GelCWWAxWR4liCjhMSy8nX/pKRDs9tNfv\n9ygBENkFkGXDw+Hb2HkcQN4+iDW9+55wPOTvyMZkNWMDDI11CooDnynicinx\nM4Cn+yx8H5ND5jO5gEj79OrtO/L+LU3Di1iGZhprvAyrSqVwyaQY1t9+BH79\n0sPHi165JQldg4JUWOK7dfpzOo6mtHinlbssRIHqcw1M26eo7Z35C8KxY5yz\nDgwufaF9Wywlwt6enZwDVt3Jb0A8Fqmh99eWHHZZJ5lwn2w+xFOFDn00xfJl\n/RcoSwtekFomCOysAyKadAVJr2B34Xj1ISCR/JvZl5erjdGBbpFC63Cgk6FH\nFjeJ1dITHilaakNLmtRrl9QXcy13WkMTI+Xv8JzdqQsX3np3r4zgJsvJNCvt\nFXuoBA==";
        assertTrue( str.equals( new String( hybrid.decryptWithPublicKey( Base64.decode( resStr ) ), "UTF-8" ) ) );
    }

    private void doOneTest( String resStr )
            throws UnsupportedEncodingException, CryptoException {
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

    private void doOneTestWithBase64( String resStr )
            throws UnsupportedEncodingException, CryptoException {
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
