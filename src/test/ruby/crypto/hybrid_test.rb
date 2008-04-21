require 'test/unit'
require 'base64'
require 'crypto/hybrid'

module Crypto
  class HybridTest < Test::Unit::TestCase
    def setup
      privkey = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/main/resources/private.pem' )
      privpass = 'iloveyou'
      asim = Crypto::Asymmetric.new( :private_key => privkey, :private_key_password => privpass )
      @sim = Crypto::Hybrid.new( asim )
    end
    
    def test_encrypt_decrypt
      str = "abcdefghijklmnopqrstuvwxyz"
      encStr = @sim.encrypt( str )
      p encStr.length
      str2 = @sim.decrypt( encStr )
      assert_equal( str, str2 )
    end
  end
end
