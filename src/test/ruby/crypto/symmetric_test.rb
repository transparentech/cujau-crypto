require 'test/unit'
require 'base64'
require 'crypto/symmetric'

module Crypto
  class SymmetricTest < Test::Unit::TestCase
    def setup
      @sim = Crypto::Symmetric.new
    end
    
    def test_random_key
      key = @sim.get_random_key
      assert_not_nil( key )
      
      keyStr = Base64.encode64( key )
      assert_not_equal( keyStr, Base64.encode64( @sim.get_random_key ) )
    end
    
    def test_random_iv
      iv = @sim.get_random_iv
      assert_not_nil( iv )

      ivStr = Base64.encode64( iv )
      assert_not_equal( ivStr, Base64.encode64( @sim.get_random_iv ) )
    end
    
    def test_symmetric_encrypt_decrypt
      key = @sim.get_random_key
      iv = @sim.get_random_iv
      
      str = "abcdefghijklmnopqrstuvwxyz"
      assert_equal( 26, str.length )

      encStr = @sim.encrypt( str, key, iv )
      #puts "encStr=#{Base64.encode64( encStr )}"
      assert_equal( 32, encStr.length )
      
      deStr = @sim.decrypt( encStr, key, iv )
      assert_equal( str, deStr )
    end
    
    def test_symmetric_encrypt
      key = @sim.get_random_key
      iv = @sim.get_random_iv
      
      str = "abcdefghijklmnopqrstuvwxyz"
      encStr = @sim.encrypt( str, key, iv )
      assert_equal( 32, encStr.length )
      
      puts "encStr='#{Base64.encode64( encStr ).strip}'"
      puts "key='#{Base64.encode64( key ).strip}'"
      puts "iv='#{Base64.encode64( iv ).strip}'"
    end
    
    def test_symmetric_decrypt
      origStr = "abcdefghijklmnopqrstuvwxyz"

      # this was generated from the ruby above.
      key = Base64.decode64( 'tPzm81tNV4DuIQfC6ZpsAQ==' )
      iv = Base64.decode64( '5M0fnVj86rA/r2pKbypjOA==' )
      encStr = Base64.decode64( 'hozAHHwsCkoNkzkP2EHDVzsCxr9S6SNQEcJn44hWxwg=' )
      
      str = @sim.decrypt( encStr, key, iv )
      assert_equal( origStr, str )
      
      # This was generated from java.
      key = Base64.decode64( 'YdBo7MahsuC0XDzpnYBgSA==' )
      iv = Base64.decode64( 'X6rMYp4Fz472eRemJcojcA==' )
      encStr = Base64.decode64( 'fyzDta2O9SEpoyDMza4r6jAzc0v3FDLwx0M2HOwY9Cc=' )
      
      str = @sim.decrypt( encStr, key, iv )
      assert_equal( origStr, str )
    end
  end
end
