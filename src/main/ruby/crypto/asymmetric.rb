require 'openssl'
require 'digest/sha1'

module Crypto
  class Asymmetric
    def initialize( options={ } )
      opts = { 
        :private_key_password => nil, 
        :public_key => nil, 
        :private_key => nil 
      }.merge( options )
      self.private_key= opts[:private_key], opts[:private_key_password]
      self.public_key= opts[:public_key]
      self.public_key= @private_key if @public_key.nil?
    end
    
    def public_key()
      @public_key
    end
    
    def public_key=( args )
      key, pass = parse_set_args( args )
      
      if key.nil?
        @public_key = nil
      elsif key.is_a?( OpenSSL::PKey::RSA )
        if key.public?
          @public_key = key
        else
          @public_key = key.public_key
        end
      else
        pk = OpenSSL::PKey::RSA.new( key, pass )
        if pk.public?
          @public_key = pk
        else
          @public_key = pk.public_key
        end
      end
    end
    
    def private_key()
      @private_key
    end
    
    def private_key=( args )
      key, pass = parse_set_args( args )

      if key.nil?
        @private_key = nil
      elsif key.is_a?( OpenSSL::PKey::RSA )
        if key.private?
          @private_key = key
        else
          @private_key = nil
        end
      else
        pk = OpenSSL::PKey::RSA.new( key, pass )
        if pk.private?
          @private_key = pk
        else
          @private_key = nil
        end
      end
    end
    
    def encrypt_with_public_key( data )
      @public_key.public_encrypt( data )
    end
    
    def encrypt_with_private_key( data )
      @private_key.private_encrypt( data )
    end
    
    def decrypt_with_public_key( data )
      @public_key.public_decrypt( data )
    end
    
    def decrypt_with_private_key( data )
      @private_key.private_decrypt( data )
    end

    private
    
    def parse_set_args( args )
      #puts "args=#{args.inspect}"
      if args.nil?
        [ nil, nil ]
      elsif args.is_a?( Array )
        key = nil
        key = args[0] if args.length > 0
        pass = nil
        pass = args[1] if args.length > 1
        #puts "args=#{args.inspect}"
        [ key, pass ]
      else
        [ args, nil ]
      end
    end
  end
end
