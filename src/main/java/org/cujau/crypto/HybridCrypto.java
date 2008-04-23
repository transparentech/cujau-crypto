package org.cujau.crypto;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HybridCrypto {

    private static final Logger LOG = LoggerFactory.getLogger( HybridCrypto.class );

    private AsymmetricCrypto asymmetric;
    private SymmetricCrypto symmetric;

    public HybridCrypto( AsymmetricCrypto asym ) {
        this.asymmetric = asym;
        try {
            this.symmetric = new SymmetricCrypto();
        } catch ( CryptoException e ) {
            LOG.warn( "This should never happen: ", e );
        }
    }

    public byte[] encryptWithPrivateKey( byte[] data )
            throws CryptoException {
        SecretKey key = symmetric.getRandomKey();
        IvParameterSpec iv = symmetric.getRandomIV();

        byte[] encData = symmetric.encrypt( data, key, iv );
        byte[] encKey = asymmetric.encryptWithPrivateKey( key.getEncoded() );
        byte[] encIv = asymmetric.encryptWithPrivateKey( iv.getIV() );

        return bundle( encData, encKey, encIv );
    }

    public byte[] encryptWithPublicKey( byte[] data )
            throws CryptoException {
        SecretKey key = symmetric.getRandomKey();
        IvParameterSpec iv = symmetric.getRandomIV();

        byte[] encData = symmetric.encrypt( data, key, iv );
        byte[] encKey = asymmetric.encryptWithPublicKey( key.getEncoded() );
        byte[] encIv = asymmetric.encryptWithPublicKey( iv.getIV() );

        return bundle( encData, encKey, encIv );
    }

    public byte[] decryptWithPublicKey( byte[] encBundle )
            throws CryptoException {
        byte[] encKey = new byte[asymmetric.getKeySizeBytes()];
        byte[] encIv = new byte[asymmetric.getKeySizeBytes()];
        byte[] encData = new byte[encBundle.length - asymmetric.getKeySizeBytes() * 2];

        unbundle( encBundle, encData, encKey, encIv );
        SecretKey key = symmetric.getKeyFromBytes( asymmetric.decryptWithPublicKey( encKey ) );
        IvParameterSpec iv = symmetric.getIvFromBytes( asymmetric.decryptWithPublicKey( encIv ) );
        
        return symmetric.decrypt( encData, key, iv );
    }

    public byte[] decryptWithPrivateKey( byte[] encBundle )
            throws CryptoException {
        byte[] encKey = new byte[asymmetric.getKeySizeBytes()];
        byte[] encIv = new byte[asymmetric.getKeySizeBytes()];
        byte[] encData = new byte[encBundle.length - asymmetric.getKeySizeBytes() * 2];

        unbundle( encBundle, encData, encKey, encIv );
        SecretKey key = symmetric.getKeyFromBytes( asymmetric.decryptWithPrivateKey( encKey ) );
        IvParameterSpec iv = symmetric.getIvFromBytes( asymmetric.decryptWithPrivateKey( encIv ) );

        return symmetric.decrypt( encData, key, iv );
    }

    private void unbundle( byte[] encBundle, byte[] encData, byte[] encKey, byte[] encIv ) {
        System.arraycopy( encBundle, 0, encIv, 0, asymmetric.getKeySizeBytes() );
        System.arraycopy( encBundle, asymmetric.getKeySizeBytes(), encKey, 0, asymmetric.getKeySizeBytes() );
        System.arraycopy( encBundle, asymmetric.getKeySizeBytes() * 2, encData, 0, encData.length );
    }

    private byte[] bundle( byte[] encData, byte[] encKey, byte[] encIv ) {
        byte[] encBundle = new byte[encData.length + encKey.length + encIv.length];
        System.arraycopy( encIv, 0, encBundle, 0, encIv.length );
        System.arraycopy( encKey, 0, encBundle, encIv.length, encKey.length );
        System.arraycopy( encData, 0, encBundle, encIv.length + encKey.length, encData.length );
        return encBundle;
    }
}
