require 'crypto/asymmetric'
require 'crypto/symmetric'

module Crypto
  class Hybrid
    def initialize( asym )
      @asymmetric = asym
      @symmetric = Crypto::Symmetric.new()
    end
    
    def encrypt_with_private_key( data )
      iv = @symmetric.random_iv
      key = @symmetric.random_key

      return @asymmetric.encrypt_with_private_key( iv ) << 
        @asymmetric.encrypt_with_private_key( key ) << 
        @symmetric.encrypt( data, key, iv )
    end
    
    def encrypt_with_public_key( data )
      iv = @symmetric.random_iv
      key = @symmetric.random_key

      return @asymmetric.encrypt_with_public_key( iv ) << 
        @asymmetric.encrypt_with_public_key( key ) << 
        @symmetric.encrypt( data, key, iv )
    end
    
    def decrypt_with_public_key( enc_bundle )
      iv = @asymmetric.decrypt_with_public_key( enc_bundle[0..255] )
      key = @asymmetric.decrypt_with_public_key( enc_bundle[256..511] )
      @symmetric.decrypt( enc_bundle[512..-1], key, iv )
    end

    def decrypt_with_private_key( enc_bundle )
      iv = @asymmetric.decrypt_with_private_key( enc_bundle[0..255] )
      key = @asymmetric.decrypt_with_private_key( enc_bundle[256..511] )
      @symmetric.decrypt( enc_bundle[512..-1], key, iv )
    end
  end
end
