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
      puts "encStr='#{Base64.encode64( encStr )}'"

      encStr = @sim.encrypt_with_private_key( str )
      puts "encStr='#{Base64.encode64( encStr )}'"
    end
    
    def test_decrypt
      str = "abcdefghijklmnopqrstuvwxyz"

      strEnc = "S4fFQ8bKrvQddTY966/OOB26rNKH9X0f4Qnx9lIytrcrRTFHNm6DWAiwoqkAUX2vZCVt2Xc8MA6B
v/NhWwAWMgQSaQ3LAPpP/RqRxQDpXG2tX42LF09pmXDQe+4Fl3Ii8uD/QP3QRVgli/Ajomi0K1zO
oOG8Q6Q9nRzJRU28SNT7O9m8TkJPI440tpfrKk7Zfw8bioUZExTdeXJZF6DUtw+9yUM9re9vbkcR
IcwznuDl/D4Achiv4aUJcSYNf68jFBd4EgwycDNz/cZI/XM+Dl2DlU2ZCkEaJtTbkBopdmaco2zn
bjO7Igu5/Se9ALnwCeTRmwTarelAFLoZUrXitkxGcCO+7amVzdnIhMVs+HnrxSlU4Vt/FSW+sU6E
S9WR95vZ9qP1mu7zCw9W0hIzBBKHm/3CtFt+TwDDbZ39xhLshg3dfq59pmn6AjazsK1RX3y9I9Nn
NWVJkVjlLfYbgBCvsoTMAE/Wql7wMFTKv0wGLdAB/mRrcBFHMTI88CvymKJ1jLm6QRu5WVmmMPg9
uLSAeYUYnLoEiNDUWS2EKWmNPanaQbgS/uq+3RnNmM/DUHspXKa0DQbWM6Tpmx1w5IN7UXyPBs6Z
cGCUFRlM4wlix4tvVbCBs59UZe6knmcHPQKh8lHOBPbTUW2rTxaeWzZontEG8ExICCl9O8iJ7U23
utdYjA0X6/BK/lX4kNZR/+1sBpq7y21eRMpQ8TFvVA=="
      str2 = @sim.decrypt_with_public_key( Base64.decode64( strEnc ) )
      assert_equal( str, str2 )
      
      strEnc = "B4G+IMj+I5gh/5V5mkwIQ+mE1yG1HPI5YNy7gv1DZjplF++JJL/fXt3egTAnxnkfyBKg/DrQtTjV
vs6wbI08aq256qCjTIwvbOT5hG9x6QSLTNnf/BF1fT6eB71VCWU5BA0IDb5uH6qyzF2Qo9+K6R/o
Sx8MNurRLN/0c83xPKqjL4re4IzsVWTfUxnACECIVrber7mXZAd7daBauU28bEWRT51mmbN1Gpla
cGH9JZyOnJGOHr5TVwvHnJUCHZAzlJbpby3UJPLqTPFIs8HevGe3y9uebCeTNMmwsRzu7C4ACFdr
RwvvtHHEBx24qFgSIf3JxkKJ/1oDIcSG/ePvIzW6mPbN2SGBIBV4md/ftWMumgxWqbqiZz/vbrUA
04JdM7FcIOOPAj+/A9TwxOQrZ3DFfrCfDjVHApk/Y4bX0T9DAbzqVwUuo9VGJIvRSQtysXwRZFvA
ZVas0P1H4z9c5kgZeRhVAuXN93Se1rE60+68iynNyt7OaVV2qeCA4YtCNmsTTBGb0/34BE7ufKbd
MRz7jPYSFxG5n3UFK+bhn3F13yAJwp0TlY+SD0s1ktzF3vlJwQnAl6EQ6rLPD0wbUXDv0QnFspPQ
+O3kOB6K68ltrF+9g1vUVLJEfnK/iOcvBaHFPmJn9YwGmVsNsKjIVNRISctJfyYA4gSJ5QIapblc
CvUgxZmp+LHxNdg7aonL8sUXXfDJ9KTabqqwMFXLwA=="
      str2 = @sim.decrypt_with_private_key( Base64.decode64( strEnc ) )
      assert_equal( str, str2 )
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
