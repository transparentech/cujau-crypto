require 'test/unit'

ENV['CUJAU_CRYPTO_HOME'] = File.dirname( File.dirname( File.dirname( File.dirname( File.expand_path(__FILE__) ) ) ) )
$LOAD_PATH.unshift( File.join( ENV['CUJAU_CRYPTO_HOME'], 'src/main/ruby' ) )
$LOAD_PATH.unshift( File.join( ENV['CUJAU_CRYPTO_HOME'], 'src/test/ruby' ) )

require 'crypto/symmetric_test'
require 'crypto/asymmetric_test'
require 'crypto/hybrid_test.rb'
