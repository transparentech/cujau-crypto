require 'base64'
require 'openssl'
require 'digest/sha1'

$cipher_string = 'aes-128-cbc'

# Format used by Ruby.
# openssl genrsa -aes256 -out private.pem 2048
# Format used by Java.
# openssl pkcs8 -topk8 -inform PEM -in private.pem -outform DER -nocrypt -out private.der
$private_key_file = File.read( File.expand_path( "./private.pem" ) )
$private_key_file_password = 'iloveyou'
# Format used by Ruby.
# openssl rsa -in private.pem -out public.pem -outform PEM -pubout
# Format used by Ruby and Java.
# openssl rsa -in private.pem -pubout -outform DER -out public.der
$public_key_file = File.read( File.expand_path( "./public.der" ) )

def encrypt_with_publickey( data ) 
  public_key = OpenSSL::PKey::RSA.new($public_key_file)
  cipher = OpenSSL::Cipher::Cipher.new($cipher_string)
  cipher.encrypt
  cipher.key = random_key = cipher.random_key
  cipher.iv = random_iv = cipher.random_iv

  ret = []
  encrypted_data = cipher.update(data)
  encrypted_data << cipher.final
  File.open( "/tmp/encout2.txt", "w" ) { |io|
    io.write( encrypted_data )
  }
  ret << Base64.encode64( encrypted_data )
  # add encrypted_key
  ret << Base64.encode64( public_key.public_encrypt(random_key) )
  # add encrypted_iv
  ret << Base64.encode64( public_key.public_encrypt(random_iv) )
  return ret
end

def encrypt_with_privatekey( data ) 
  private_key = OpenSSL::PKey::RSA.new($private_key_file, $private_key_file_password)
  cipher = OpenSSL::Cipher::Cipher.new($cipher_string)
  cipher.encrypt
  cipher.key = random_key = cipher.random_key
  cipher.iv = random_iv = cipher.random_iv

  ret = []
  encrypted_data = cipher.update(data)
  encrypted_data << cipher.final
  ret << Base64.encode64( encrypted_data )
  # add encrypted_key
  ret << Base64.encode64( private_key.private_encrypt(random_key) )
  # add encrypted_iv
  ret << Base64.encode64( private_key.private_encrypt(random_iv) )
  return ret
end

def decrypt_with_privatekey( encary )
  private_key = OpenSSL::PKey::RSA.new($private_key_file, $private_key_file_password)
  cipher = OpenSSL::Cipher::Cipher.new($cipher_string)
  cipher.decrypt
  cipher.key = private_key.private_decrypt(Base64.decode64(encary[1]))
  cipher.iv = private_key.private_decrypt(Base64.decode64(encary[2]))
  
  decrypted_data = cipher.update(Base64.decode64(encary[0]))
  decrypted_data << cipher.final
  return decrypted_data
end

def decrypt_with_publickey( encary )
  public_key = OpenSSL::PKey::RSA.new($public_key_file)
  cipher = OpenSSL::Cipher::Cipher.new($cipher_string)
  cipher.decrypt
  cipher.key = public_key.public_decrypt(Base64.decode64(encary[1]))
  cipher.iv = public_key.public_decrypt(Base64.decode64(encary[2]))
  
  decrypted_data = cipher.update(Base64.decode64(encary[0]))
  decrypted_data << cipher.final
  return decrypted_data
end

if $0 == __FILE__

  message = "This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text.This is some cool text."

  encstuff = encrypt_with_publickey( message )
  puts encstuff.inspect
  puts decrypt_with_privatekey( encstuff )

  encstuff = encrypt_with_privatekey( message )
  puts encstuff.inspect
  puts decrypt_with_publickey( encstuff )
end
