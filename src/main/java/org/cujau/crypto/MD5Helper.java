package org.cujau.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Helper {

    /**
     * Convert the array of String to bytes to use for the salt.
     * 
     * @param saltStringBytes
     *            Each element of the array must be convertable to a byte, otherwise it is ignored.
     * @return The salt string bytes as bytes.
     */
    public static byte[] toSaltBytes( String[] saltStringBytes ) {
        byte ret[] = new byte[saltStringBytes.length];
        for ( int i = 0; i < saltStringBytes.length; i++ ) {
            ret[i] = Byte.parseByte( saltStringBytes[i] );
        }
        return ret;
    }

    public static String toMD5String( byte[] valBytes )
            throws NoSuchAlgorithmException {
        byte[] md = toMD5Bytes( valBytes );
        return md5BytesAsString( md );
    }

    public static String toMD5String( byte[] valBytes, byte[] salt )
            throws NoSuchAlgorithmException {
        byte[] md = toMD5Bytes( valBytes, salt );
        return md5BytesAsString( md );
    }

    public static byte[] toMD5Bytes( byte[] valBytes )
            throws NoSuchAlgorithmException {
        MessageDigest algorithm = MessageDigest.getInstance( "MD5" );
        algorithm.reset();
        algorithm.update( valBytes );
        return algorithm.digest();
    }

    public static byte[] toMD5Bytes( byte[] valBytes, byte[] salt )
            throws NoSuchAlgorithmException {
        MessageDigest algorithm = MessageDigest.getInstance( "MD5" );
        algorithm.reset();
        algorithm.update( salt );
        algorithm.update( valBytes );
        return algorithm.digest();
    }

    private static String md5BytesAsString( byte[] md ) {
        StringBuilder hexString = new StringBuilder();
        for ( int i = 0; i < md.length; i++ ) {
            String hex = Integer.toHexString( 0xFF & md[i] );
            if ( hex.length() == 1 ) {
                hexString.append( '0' );
            }
            hexString.append( hex );
        }
        return hexString.toString();
    }
}
