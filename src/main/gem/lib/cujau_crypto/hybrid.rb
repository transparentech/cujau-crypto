#require 'crypto/asymmetric'
#require 'crypto/symmetric'

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
      bundle_key_iv = get_encrypted_key_iv( enc_bundle )
      iv = @asymmetric.decrypt_with_public_key( bundle_key_iv[0] )
      key = @asymmetric.decrypt_with_public_key( bundle_key_iv[1] )
      symmetric_decrypt( enc_bundle, key, iv )
    end

    def decrypt_with_private_key( enc_bundle )
      bundle_key_iv = get_encrypted_key_iv( enc_bundle )
      iv = @asymmetric.decrypt_with_private_key( bundle_key_iv[0] )
      key = @asymmetric.decrypt_with_private_key( bundle_key_iv[1] )
      symmetric_decrypt( enc_bundle, key, iv )
    end
    
    private
    
    def get_encrypted_key_iv( enc_bundle )
      ret = []
      ret << enc_bundle[0..(@asymmetric.key_size_bytes - 1)]
      ret << enc_bundle[@asymmetric.key_size_bytes..(@asymmetric.key_size_bytes*2-1)]
      ret
    end
    
    def symmetric_decrypt( enc_bundle, key, iv )
      @symmetric.decrypt( enc_bundle[(@asymmetric.key_size_bytes*2)..-1], key, iv )
    end
    
  end
end
