require 'test/unit'
require 'base64'
require 'crypto/hybrid'

module Crypto
  
  PRIVATE_KEY_RESOURCE = '/cujau-priv.key'
  PRIVATE_KEY_PASSWORD = 'iloveyou'
  PUBLIC_KEY_RESOURCE = '/cujau-pub.key'

  class HybridTest < Test::Unit::TestCase
    def setup
      privkey = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources' + PRIVATE_KEY_RESOURCE )
      privpass = PRIVATE_KEY_PASSWORD

      asim = Crypto::Asymmetric.new( :private_key => privkey, :private_key_password => privpass )
      @sim = Crypto::Hybrid.new( asim )
    end
    
    def test_encrypt_decrypt
      str = "abcdefghijklmnopqrstuvwxyz"
      do_one_test( str )
      
      str = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources/testBigText.txt' )
      do_one_test( str )
      
      str = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources/testXMLText.xml' )
      do_one_test( str )
    end
    
    def test_encrypt_decrypt_with_base64
      str = "abcdefghijklmnopqrstuvwxyz"
      do_one_test_with_base64( str )
      
      str = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources/testBigText.txt' )
      do_one_test_with_base64( str )
      
      str = File.read( ENV['CUJAU_CRYPTO_HOME'] + '/src/test/resources/testXMLText.xml' )
      do_one_test_with_base64( str )
    end
    
    def test_encrypt
      str = "abcdefghijklmnopqrstuvwxyz"
      
      encStr = @sim.encrypt_with_public_key( str )
      puts "HYB:pubEnc='#{Base64.encode64( encStr )}'"

      encStr = @sim.encrypt_with_private_key( str )
      puts "HYB:privEnc='#{Base64.encode64( encStr )}'"
    end
    
    def test_decrypt
      str = "abcdefghijklmnopqrstuvwxyz"

      strEnc = 'J6cSRl7grbhSBAKq8pIGaw6ZwFUylRlfyQVp6tZtNbjU40YdWzlVng+Hvwq0Usg3SAzyoFz08+y5
0Fb/23vlr1VPHZZfCuqRNLxbhXB8+LbwJoPMYb4CuiUUaR4uUKyZZwxZ94IKUHBO19FhEX1HaYv/
mL8mGof0DCbpv3RP+Zgzjb/aCDVoFEZKjtI+VITSPBrHFJ1qpqdylg8A7ApTVQneDtjxFfGikC7C
WKBtr7FSzj/1p3FJXvv5Mvbsyo2vQMYMnz7tr+TcH9c8tOC7wbXZh+UrivJ7NWHbE8UUI36IVj+E
Kr4clOWobq5KIffn53ZujUp6Bf/Z2rHvClxZgmH50D5nnakhpFXwENefC0woIFTJQ8tTb1Yvh4zd
zbHJ30z7IqJCQ+R+1QyhQJfyrHzI+elB0hZdcXdKcxnrv8OXGowaaOvB/sjuQcoLhKgtnUi2r973
GKBEP1exVgtZAvVrJu642xpNH4Ha8Zs4mldqau9D+v7Ho7wTcCJoR6cu48DDcDbgokFhiwFdlblA
Zo+f3uaiat14tRhzwvNEy9jMf7oOYsnWzEzWrgKiLba8IGdXIRrrwRX89QL1KLre0pxuSW05+Yvt
lRnOZOlLGcCJHj/z2n+htTaLgJ8FxUIo8lK9G69eY7E/d9NvJqDQuCmGFMt3uIHrNBIONY46Asl8
M/b62GZ1gNyo/GQ28i3NxB30SeAoQE77eu63wkvnTQ=='
      str2 = @sim.decrypt_with_public_key( Base64.decode64( strEnc ) )
      assert_equal( str, str2 )
      
      strEnc = 'jczswveXfulamElqSBv/n82eII/eG0kW/a0aqZOtcG/if7E7r0Zz19U3xYJvrD4Z8+GwFEXvr+7S
DyJ4Ml7dmVPIdNW8Ng789bEbiF3XrBy3D1BaVUNzLXbu+C9/qJkBQ9A6fVEmzT7SUgbbQuYVpVAk
nZXjdBG5fQsQL/mI0o1pBvCysvqKNuaT0/zPCwP5aqzYurxgWOI9cFyYPZ0e6o0fwF71Dezo085V
MKV9w6JOVDwCvMWY0XeZTvLogkt7olq9W2VA9v+jcEiyRZqtsR5ZNbdBbMrfFcSSoLr0hUT6lHma
hem3qqufw2dTJxBKRxKt4K3HiRw2bPDg+req7X+6iKrD44ITzwQYI03KG69NCH8+s4niuABOC+tK
NtFOESxa/TekLNkXRRzAhqi3W6mwTJdnvegjvZetF7o7vwQxvIKxkIUymLDt84C3Hq/WTchw0WiD
4unT3QNg3q3hYGXGBO+HNExOd7SqFYp1a7sau+1eKhXtesesGY7uoD9+HWPfXY1B+KRTQLozr9Hl
zfFwq4AoYmsFCObKxXfXAkiAiZk2WLo6S2AmS/b9Ix9SUTfWf2asbRWJq1WFpowx9yjIYl1xo0Zg
usPd9bIri6MbL/MTuUnEw4yCE0rX2Zj2rdoMURYBqYhi4VS16JIntymTAxsIC/FL3AdVRpN+PSvK
jgEdR8+yjmAFE3AbIg1cfjhF+QJTYUOTsqAG77JyRA=='
      str2 = @sim.decrypt_with_private_key( Base64.decode64( strEnc ) )
      assert_equal( str, str2 )
    end
    
    def test_license_encrypt
      licStr = %q{ 
com.sme.license.owner=Nicholas Rahn
com.sme.license.expirationDate=2010-01-01 00:00:00
com.sme.license.type=GOLD
}
      encStr = @sim.encrypt_with_private_key( licStr )
      puts "license='#{Base64.encode64( encStr )}'"
    end
    
    private
    
    def do_one_test( str )
      encStr = @sim.encrypt_with_public_key( str )
      str2 = @sim.decrypt_with_private_key( encStr )
      assert_equal( str, str2 )

      encStr = @sim.encrypt_with_private_key( str )
      str2 = @sim.decrypt_with_public_key( encStr )
      assert_equal( str, str2 )
    end

    def do_one_test_with_base64( str )
      encStr = Base64.encode64( @sim.encrypt_with_public_key( str ) )
      str2 = @sim.decrypt_with_private_key( Base64.decode64( encStr ) )
      assert_equal( str, str2 )

      encStr = Base64.encode64( @sim.encrypt_with_private_key( str ) )
      str2 = @sim.decrypt_with_public_key( Base64.decode64( encStr ) )
      assert_equal( str, str2 )
    end
end
end
