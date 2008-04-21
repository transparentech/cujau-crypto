package org.cujau.crypto;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Crypto {
    
    private static final Logger LOG = LoggerFactory.getLogger( Crypto.class );
    
    private AsymmetricCrypto asymmetric;
    private SymmetricCrypto symmetric;

    public Crypto( AsymmetricCrypto asym ) {
        this.asymmetric = asym;
        try {
            this.symmetric = new SymmetricCrypto();
        } catch ( CryptoException e ) {
            LOG.warn( "This should never happen: ", e );
        }
    }
    
    public byte[] encrypt( byte[] data ) throws CryptoException {
        SecretKey key = symmetric.getRandomKey();
        IvParameterSpec iv = symmetric.getRandomIV();
        
        byte[] encData = symmetric.encrypt( data, key, iv );
        byte[] encKey = asymmetric.encryptWithPrivateKey( key.getEncoded() );
        byte[] encIv = asymmetric.encryptWithPrivateKey( iv.getIV() );

        byte[] encBundle = new byte[encData.length + encKey.length + encIv.length];
        System.arraycopy( encIv, 0, encBundle, 0, encIv.length );
        System.arraycopy( encKey, 0, encBundle, encIv.length, encKey.length );
        System.arraycopy( encData, 0, encBundle, encIv.length + encKey.length, encData.length );
        
        return encBundle;
    }
    
    public byte[] decrypt( byte[] encBundle ) throws CryptoException {
        byte[] encKey = new byte[256];
        byte[] encIv = new byte[256];
        byte[] encData = new byte[encBundle.length - 512];
        
        System.arraycopy( encBundle, 0, encIv, 0, 256 );
        System.arraycopy( encBundle, 256, encKey, 0, 256 );
        System.arraycopy( encBundle, 512, encData, 0, encData.length );

        SecretKey key = symmetric.getKeyFromBytes( asymmetric.decryptWithPublicKey( encKey ) );
        IvParameterSpec iv = symmetric.getIvFromBytes( asymmetric.decryptWithPublicKey( encIv ) );
        byte[] data = symmetric.decrypt( encData, key, iv );
        
        return data;
    }
}
