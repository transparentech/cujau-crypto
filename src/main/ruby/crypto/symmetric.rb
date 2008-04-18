require 'openssl'
require 'digest/sha1'

module Crypto
  class Symmetric

    @@DEFAULT_ALGORITHM_NAME = "aes-128-cbc"

    def initialize( algorithm = @@DEFAULT_ALGORITHM_NAME )
      @algorithm = algorithm
    end

    def random_key()
      cipher = new_cipher( @algorithm )        
      cipher.random_key
    end

    def random_iv()
      cipher = new_cipher( @algorithm )
      cipher.random_iv
    end

    def encrypt( data, key, iv )
      cipher = new_cipher( @algorithm )
      cipher.encrypt
      crypt( cipher, data, key, iv )
    end

    def decrypt( data, key, iv )
      cipher = new_cipher( @algorithm )
      cipher.decrypt
      crypt( cipher, data, key, iv )
    end

    private

    def crypt( cipher, data, key, iv )
      cipher.key = key
      cipher.iv = iv
      encrypted_data = cipher.update(data)
      encrypted_data << cipher.final
      return encrypted_data
    end

    def new_cipher( algorithm )
      OpenSSL::Cipher::Cipher.new( algorithm )
    end

  end
end
