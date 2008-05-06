require 'test/unit'
require 'base64'
require 'crypto/asymmetric'

module Crypto
  
  PRIVATE_KEY_RESOURCE = '/cujau-priv.key'
  PRIVATE_KEY_PASSWORD = 'iloveyou'
  PUBLIC_KEY_RESOURCE = '/cujau-pub.key'
  
  class AsymmetricTest < Test::Unit::TestCase
    def setup
      privkey = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources' + PRIVATE_KEY_RESOURCE )
      privpass = 'iloveyou'
      @asim = Crypto::Asymmetric.new( :private_key => privkey, :private_key_password => PRIVATE_KEY_PASSWORD )
    end
    
    def test_initialize
      pubkey = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources' + PUBLIC_KEY_RESOURCE )
      privkey = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources' + PRIVATE_KEY_RESOURCE )
      privpass = PRIVATE_KEY_PASSWORD
      
      @asim = Crypto::Asymmetric.new( :public_key => pubkey )
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.public? )
      assert_nil( @asim.private_key )
      assert_equal( 256, @asim.key_size_bytes )
      
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
      pubkeyFile = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources' + PUBLIC_KEY_RESOURCE )
      privkeyFile = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources' + PRIVATE_KEY_RESOURCE )
      privpass = PRIVATE_KEY_PASSWORD
      
      pubkey = OpenSSL::PKey::RSA.new( pubkeyFile )
      @asim.public_key = pubkey
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.public_key.public? )

      privkey = OpenSSL::PKey::RSA.new( privkeyFile, privpass )
      @asim.public_key = privkey
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.public_key.public? )

      @asim.public_key = nil
      assert_nil( @asim.public_key )

      @asim.public_key = pubkeyFile
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.public_key.public? )

      @asim.public_key = privkeyFile, privpass
      assert_not_nil( @asim.public_key )
      assert( @asim.public_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.public_key.public? )
    end

    def test_set_private_key
      pubkeyFile = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources' + PUBLIC_KEY_RESOURCE )
      privkeyFile = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources' + PRIVATE_KEY_RESOURCE )
      privpass = PRIVATE_KEY_PASSWORD
      
      privkey = OpenSSL::PKey::RSA.new( privkeyFile, privpass )
      @asim.private_key = privkey
      assert_not_nil( @asim.private_key )
      assert( @asim.private_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.private_key.private? )

      pubkey = OpenSSL::PKey::RSA.new( pubkeyFile )
      @asim.private_key = pubkey
      assert_nil( @asim.private_key )

      @asim.private_key = privkeyFile, privpass
      assert_not_nil( @asim.private_key )
      assert( @asim.private_key.is_a?( OpenSSL::PKey::RSA ) )
      assert( @asim.private_key.private? )

      @asim.private_key = pubkeyFile
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
      puts "ASYM:pubEnc='#{Base64.encode64( strEnc ).strip}'"
      
      strEnc = @asim.encrypt_with_private_key( str )
      puts "ASYM:privEnc='#{Base64.encode64( strEnc ).strip}'"
    end

    def test_asymmetric_decrypt
      str = "abcdefghijklmnopqrstuvwxyz"

      strEnc = 'dYj9Y21SWvumI75K/AyXUkEYMNR0fWmXAg7w8igKWOB91MyE4NX0fHQQmwgOovUMgF7wtyh9B9wG
bEBlDBbGT5Q5xDzopRip5DzKsFWMqjadxNdEDWQDkAsz/8PmPp9fBOIIFA7AjYowTETPDC6RrCPy
jBtrqKGNmSXMhGgUYTJMUoprQSflxJCiWZn6nPdVy3W/i+rrUD0Uh/v0Yc6Chzdb5fzqPN9juou5
r3sel5L3d8yvlrG29ZqUf4SOICLZxC/0f2gcnoetcwsGfJVmwHacf/h4ycRqk7S3xYfXp0AP8MSW
kc/iqKQc3mLF5GKK03Jueuxx5dJJVfKyMyObaw=='
      strNew = @asim.decrypt_with_private_key( Base64.decode64( strEnc ))
      assert_equal( str, strNew )
      
      
      strEnc = 'VFdb/fg3TtWq0T6Agw9dbsigs3WG4xUjpHEDWnJIbT4YxCTiPaA+BGkt6HBdSfKutjElgXgvxuUn
L4xHbCeD9CpMQYOktVVaQA227KBjv/OUTmrwr8qJhj358RWuOtJAmvTHGSiVm5oXNbIpf7raJ+rn
D71xnMVbNTEzNonazUjIlgDzasR8DLzFsQ+vpChmnGxrfJUens8aQ7rg09SgQBQprttt8jFRJbIo
qV5sYB7E9wTHd6Wh6yc3kkdm4TK/un/nARqCwkFSP8czbAo5VFVbeyQXjkyYBDx+Aw1r2kMA7gBB
TbGW9DyHdA3SyflIxqHgMlT/qOgU+DKfTYGdgg=='
      strNew = @asim.decrypt_with_public_key( Base64.decode64( strEnc ))
      assert_equal( str, strNew )
    end
  end
end
