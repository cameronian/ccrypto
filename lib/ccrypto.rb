# frozen_string_literal: true

require 'toolrack'
require 'tlogger'

require_relative "ccrypto/version"

require_relative 'ccrypto/provider'
require_relative 'ccrypto/algo_factory'
require_relative 'ccrypto/key_bundle'
#require_relative 'ccrypto/x509_cert_profile'

require_relative 'ccrypto/asn1'
require_relative 'ccrypto/asn1_object'

#require_relative 'ccrypto/kdf_scrypt'

#require_relative 'ccrypto/cipher_config'

require_relative 'ccrypto/util_factory'

Dir.glob(File.join(File.dirname(__FILE__),"ccrypto","configs","*.rb")) do |f|
  require f
end

require_relative 'ccrypto/public_key'
require_relative 'ccrypto/secret_key'

#Dir.glob(File.join(File.dirname(__FILE__),"ccrypto","spi","*_spi.rb")) do |f|
#  require f
#end

module Ccrypto
  class Error < StandardError; end
  class CcryptoProviderException < StandardError; end

  class DigestEngineException < StandardError; end
  class KDFEngineException < StandardError; end
  class HMACEngineException < StandardError; end
  class KeypairEngineException < StandardError; end
  class KeyBundleException < StandardError; end
  class X509EngineException < StandardError; end
  class CipherEngineException < StandardError; end
  class ASN1EngineException < StandardError; end

  class CompressionError < StandardError; end
  class DecompressionException < StandardError; end

  class MemoryBufferException < StandardError; end

  class SecretSharingException < StandardError; end
  # Your code goes here...
end
