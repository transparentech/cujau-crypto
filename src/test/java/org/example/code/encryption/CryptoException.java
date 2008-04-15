package org.example.code.encryption;

public class CryptoException extends Exception {

    private static final long serialVersionUID = 1L;

    public CryptoException( Exception e ) {
        super( e );
    }
    
    public CryptoException( String msg ) {
        super( msg );
    }
}
