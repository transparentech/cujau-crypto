# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "cujau_crypto/version"

Gem::Specification.new do |s|
  s.name        = "cujau_crypto"
  s.version     = CujauCrypto::VERSION
  s.authors     = ["Nicholas Rahn"]
  s.email       = ["nick@transparentech.com"]
  s.homepage    = "http://www.transparentech.com/opensource"
  s.summary     = %q{Cujau-Crypto library}
  s.description = %q{Ruby side of the Cujau-Crypto java/ruby cryptography library.}

  s.rubyforge_project = "cujau_crypto"

  s.files = %w{.gitignore Gemfile Rakefile cujau_crypto.gemspec lib/cujau_crypto.rb lib/cujau_crypto/asymmetric.rb lib/cujau_crypto/hybrid.rb lib/cujau_crypto/symmetric.rb lib/cujau_crypto/version.rb}
#  s.files         = `git ls-files`.split("\n")
#  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
#  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  # specify any dependencies here; for example:
  # s.add_development_dependency "rspec"
  # s.add_runtime_dependency "rest-client"
end
