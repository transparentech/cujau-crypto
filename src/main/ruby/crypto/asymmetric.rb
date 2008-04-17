require 'openssl'
require 'digest/sha1'

module Crypto
  class Asymmetric
    def initialize( opts={ } )
      opts = { 
        :public_key_pem_or_dir_file => "", 
        :private_key_pem_or_dir_file => "", 
        :private_key_password => nil, 
        :public_key => nil, 
        :private_key => nil 
      }.merge( options )
    end
    
    def get_public_key
    end
    
    def get_private_key
    end
    
    def encrypt_with_public_key( data )
    end
    
    def encrypt_with_private_key( data )
    end
    
    def decrypt_with_public_key( data )
    end
    
    def decrypt_with_private_key( data )
    end
  end
end
