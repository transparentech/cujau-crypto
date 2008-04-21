require 'test/unit'
require 'base64'
require 'crypto/asymmetric'

module Crypto
  class AsymmetricTest < Test::Unit::TestCase
    def setup
      privkey = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/private.pem' )
      privpass = 'iloveyou'
      @asim = Crypto::Asymmetric.new( :private_key => privkey, :private_key_password => privpass )
    end
    
    def test_initialize
      pubkey = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/public.der' )
      privkey = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/private.pem' )
      privpass = 'iloveyou'
      
      @asim = Crypto::Asymmetric.new( :public_key => pubkey )
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.public? )
      assert_nil( @asim.private_key )

      @asim = Crypto::Asymmetric.new( :private_key => privkey, :private_key_password => privpass )
      assert_not_nil( @asim.private_key )
      assert( @asim.private_key.private? )
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.public? )

      @asim = Crypto::Asymmetric.new( :private_key => privkey, :private_key_password => privpass, 
                                      :public_key => pubkey )
      assert_not_nil( @asim.private_key )
      assert( @asim.private_key.private? )
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.public? )
    end

    def test_set_public_key
      pubkey = OpenSSL::PKey::RSA.new( File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/public.der' ) )
      @asim.public_key = pubkey
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.public_key.public? )

      privkey = OpenSSL::PKey::RSA.new( File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/private.pem' ), 
                                        'iloveyou' )
      @asim.public_key = privkey
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.public_key.public? )

      @asim.public_key = nil
      assert_nil( @asim.public_key )

      @asim.public_key = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/public.der' )
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.public_key.public? )

      @asim.public_key = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/private.pem' ), 'iloveyou'
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.public_key.public? )
    end

    def test_set_private_key
      privkey = OpenSSL::PKey::RSA.new( File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/private.pem' ), 
                                        'iloveyou' )
      @asim.private_key = privkey
      assert_not_nil( @asim.private_key )
      assert( @asim.private_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.private_key.private? )

      pubkey = OpenSSL::PKey::RSA.new( File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/public.der' ) )
      @asim.private_key = pubkey
      assert_nil( @asim.private_key )

      @asim.private_key = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/private.pem' ), 'iloveyou'
      assert_not_nil( @asim.private_key )
      assert( @asim.private_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.private_key.private? )

      @asim.private_key = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/public.der' )
      assert_nil( @asim.private_key )
    end

    def test_asymmetric_encrypt_decrypt
      str = "abcdefghijklmnopqrstuvwxyz"
      strEnc = @asim.encrypt_with_public_key( str )
      strNew = @asim.decrypt_with_private_key( strEnc )
      assert_equal( str, strNew )
      
      strEnc = @asim.encrypt_with_private_key( str )
      strNew = @asim.decrypt_with_public_key( strEnc )
      assert_equal( str, strNew )
      
      begin
        strEnc = @asim.encrypt_with_private_key( str )
        strNew = @asim.decrypt_with_private_key( strEnc )
        flunk
      rescue
        assert( true )
      end

      begin
        strEnc = @asim.encrypt_with_public_key( str )
        strNew = @asim.decrypt_with_public_key( strEnc )
        flunk
      rescue
        assert( true )
      end
    end
    
    def test_asymmetric_encrypt
      str = "abcdefghijklmnopqrstuvwxyz"
      
      strEnc = @asim.encrypt_with_public_key( str )
      puts "pubEnc='#{Base64.encode64( strEnc ).strip}'"
      
      strEnc = @asim.encrypt_with_private_key( str )
      puts "privEnc='#{Base64.encode64( strEnc ).strip}'"
    end

    def test_asymmetric_decrypt
      str = "abcdefghijklmnopqrstuvwxyz"

      strEnc = 'Uhv8A1L99UZp8tCgTxiVQY2rbI40quNnYRT+1p4xOtdGutqFbamcS0U8X7la61yMIMwkDXz3uWjm
m/rn/tUV1Q7CLcN/3ys6yEb3HoHlnn+QsAtiBtOwz4jaPs17PRfp45o9f8FOUevd4zojQ0bZ+K7T
yJHqrq0kj+SzDes5slh7xM+WTXMFowobSdZ+e/iwabHPgMZ6da28NIr7/BybaUyW9LZL3ppfygFx
iHuPwGISXncZBc/CGVT/hKrsDo3PKu+wK8gGR6QZOgjoQ9rYVL6VBTSzDPc61RxrUeVjn90+t81e
4OD7WIDQQzDJzuy/RPyx7WCbyM1jkru8U2LVlA=='
      strNew = @asim.decrypt_with_private_key( Base64.decode64( strEnc ))
      assert_equal( str, strNew )

      strEnc = 'WEkon/O7JvwctJ7hgcGRvZ/qL4yk7kofCMI++JBf6GDsUBnAtcwAzcgEj0BIRkVizVemxFtXEh3FIZmAr2TbTFsEvV0d5Wza/T8AiBWEusRu/x27Ak1fXGSzDbKdIclidbu2jFM48S56L9hkD9D7GVR9gAMOv2PcqBUBThUWuw+yDkG+ernUzEpLGGgAADU6b4GtHmmQ851bSFVVVqeG3HI1psbuM0loovJqW/PI+uYe37xikQp+RoThQmP0X2GNRZHIrcf1ZvjiWM9h0dAgE1HpMhDewF4NehfYKvqTdqmQOvCFFs+g547E51bFvVWJzwZylhZdCt19DiU23nqdKA=='
      strNew = @asim.decrypt_with_private_key( Base64.decode64( strEnc ))
      assert_equal( str, strNew )
      
      
      strEnc = 'VA0AZe+dnKGpKWogySE/2lLTybc0hefEr+6WjVWWyTexDhM9xcWzffA7HvuJiKZzLbhtRkXu7x7v
n2BpNc/FFeCMD0BpBzh6LRiKGgs3jdXtqcvoSMteFDQOJ6z3t7rpkuoJcjbHQTffXh0uXKYHzDUW
X7uxkeL/z+y5tg49KnrDZhIWWwr11emgIRla4/+43DUmwKNEzwBtlMMVASNU79tikLFKLwuSYsWC
KonWWxkEWHbsgdDnww7oXQjt1+WajT2dI/cpkY6l0uVOMhLqX9NXKrhLM7KNL6qBAlgM3ErwfMd7
xNvnXbO6JXvCAmA40nenycd5kSAvSuN9BUmffg=='
      strNew = @asim.decrypt_with_public_key( Base64.decode64( strEnc ))
      assert_equal( str, strNew )
    end
  end
end
