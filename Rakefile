require 'rubygems'
#Gem::manage_gems
require 'rake/gempackagetask'
require 'rake/testtask'
require 'fileutils'

spec = Gem::Specification.new do |s| 
  s.name = "cujau.crypto"
  s.version = "0.1.0"
  s.author = "TransparenTech LLC"
  s.email = "nick@transparentech.com"
  s.homepage = "http://www.transparentech.com/"
  s.platform = Gem::Platform::RUBY
  s.summary = "Hybrid, asymmetric and symmetric cryptography library."
  s.require_path = "lib"
  #  s.autorequire = "crypto"

  # Don't set files and test_files here. Do it in the task below.
  # s.files = FileList["lib/**/*", "src/main/ruby/**/*"].to_a
  # s.test_files = FileList["tests/**/*test.rb"].to_a

  s.has_rdoc = true
  #  s.extra_rdoc_files = ["README"]
  #  s.add_dependency("dependency", ">= 0.x.x")
end
 

task :default do 
  # Build the temporary GEM directory structure and copy the required
  # files from the Maven structure.
  mkdir_p %w( target/gem/lib target/gem/pkg target/gem/tests )
  cp_r 'src/main/ruby/.', 'target/gem/lib'
  cp_r 'src/test/ruby/.', 'target/gem/tests'

  # Switch to the temporary GEM directory and add the files from there
  # to the Gem::Specification object.
  cd 'target/gem'
  spec.files = FileList["lib/**/*"].to_a
  spec.test_files = FileList["tests/**/*.rb"]
  
  # Define the GEM building task.
  Rake::GemPackageTask.new(spec) do |pkg| 
    pkg.need_tar = true 
    p pkg
  end
 
  p spec.files.inspect
  # Call the gem task.
  Rake::Task[:gem].invoke
  
  # Copy the GEM file into the toplevel target dir.
  cp_r 'pkg/.', '..'
end

Rake::TestTask.new do |t|
  t.libs << "src/test/ruby" << "src/main/ruby"
  t.test_files = FileList["src/test/ruby/test_suite.rb"]
  t.verbose = true
end

task :genkeys, :alias, :password, :outdir  do |t, args|
  keyalias = 'cujau'
  keyalias = args[:alias] if args[:alias]
  password = 'changeit'
  password = args[:password] if args[:password]
  outdir = '/tmp'
  outdir = args[:outdir] if args[:outdir]
  
  keyalg = 'RSA'
  keysize = 2048
  validity = 999
  storetype = 'jks'
  keystore = "#{outdir}/#{keyalias}KeyStore.#{storetype}"
  pubcert = "#{outdir}/#{keyalias}-pub.cert"
  certstore = "#{outdir}/#{keyalias}CertStore.#{storetype}"
  privkey = "#{outdir}/#{keyalias}-priv.key"
  pubkey = "#{outdir}/#{keyalias}-pub.key"
  
  # Generate private/public key pair in keystore.jks
  puts "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  puts "GENERATING PRIVATE/PUBLIC KEY PAIR IN KEYSTORE (#{keystore})"
  puts "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  cmd = "keytool -genkeypair -alias #{keyalias} -keyalg RSA -keysize #{keysize} -validity #{validity} -keystore #{keystore} -storetype #{storetype} -keypass #{password} -storepass #{password}"
  puts cmd
  system cmd
  
  # Export public certificate into cujau.cer
  puts "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  puts "EXPORTING PUBLIC CERTIFICATE INTO #{pubcert}"
  puts "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  cmd = "keytool -export -keystore #{keystore} -alias #{keyalias} -file #{pubcert} -storepass #{password}"
  puts cmd
  system cmd
  
  # Import public certificate into cujauCert.jks certificate store.
  puts "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  puts "IMPORTING PUBLIC CERTIFICATE INTO CERTIFICATE STORE (#{certstore})"
  puts "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  cmd = "keytool -import -alias #{keyalias} -file #{pubcert} -storetype #{storetype} -keystore #{certstore} -storepass #{password}; rm -f #{pubcert}"
  puts cmd
  system cmd
  
  # Export the private key into pkcs8 unencrypted format suitable for the ruby side.
  puts "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  puts "EXPORTING PRIVATE KEY INTO PKCS8 FORMAT (#{privkey})"
  puts "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  cmd = "java -cp target/cujau.crypto-0.1.0-SNAPSHOT.jar org.cujau.crypto.ExportPrivateKey #{keystore} #{storetype} #{password} #{keyalias} #{privkey}"
  puts cmd
  system cmd
  
  # Export the public key into format suitable for the ruby side.
  puts "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  puts "EXPORTING PUBLIC KEY INTO #{pubkey}"
  puts "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  cmd = "openssl rsa -in #{privkey} -out #{pubkey} -outform PEM -pubout"
  puts cmd
  system cmd

  puts "\n"
  puts "Key generation completed!"
  puts "Java-side files:"
  puts "  Key Store:         #{keystore}"
  puts "  Certificate Store: #{certstore}"
  puts "Ruby-side files:"
  puts "  Private Key:       #{privkey}"
  puts "  Public Key:        #{pubkey}"
  puts "\n"
  
  # Convert the pkcs8 formatted private key to a non binary one that can be read by apache modssl.
  #
  #openssl pkcs8 -inform PEM -nocrypt -in #{privkey} -out #{privkey}.ssl

  # Convert the pkcs8 unencrypted private key to an encrypted pkcs8
  # key. You will be asked for password to use for encryption. This
  # can also be used on the ruby side (with the password, of course).
  #
  #openssl pkcs8 -inform PEM -in #{privkey} -outform PEM -out #{privkey}.pem -topk8
  
end
