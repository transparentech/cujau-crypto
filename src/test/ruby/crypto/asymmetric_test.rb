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
    end
  end
end
