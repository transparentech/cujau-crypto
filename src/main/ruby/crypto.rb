require 'crypto/asymmetric'
require 'crypto/symmetric'
require 'crypto/hybrid'

# Key creation commands and notes.
#
# ** Private keys **
# Format used by Ruby.
# openssl genrsa -aes256 -out private.pem 2048
# Format used by Java.
# openssl pkcs8 -topk8 -inform PEM -in private.pem -outform DER -nocrypt -out private.der
#
# ** Public keys **
# Format used by Ruby.
# openssl rsa -in private.pem -out public.pem -outform PEM -pubout
# Format used by Ruby and Java.
# openssl rsa -in private.pem -pubout -outform DER -out public.der

