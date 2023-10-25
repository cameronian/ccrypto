# frozen_string_literal: true

require 'toolrack'
require 'teLogger'

require_relative "ccrypto/version"

require_relative 'ccrypto/provider'
require_relative 'ccrypto/algo_factory'
require_relative 'ccrypto/key_bundle'
require_relative 'ccrypto/supported_cipher_list'

require_relative 'ccrypto/asn1'
require_relative 'ccrypto/asn1_object'

require_relative 'ccrypto/util_factory'

Dir.glob(File.join(File.dirname(__FILE__),"ccrypto","configs","*.rb")) do |f|
  require f
end

require_relative 'ccrypto/public_key'
require_relative 'ccrypto/private_key'
require_relative 'ccrypto/secret_key'

require_relative 'ccrypto/x509_cert'
require_relative 'ccrypto/x509_csr'

require_relative 'ccrypto/digest_matcher'
require_relative 'ccrypto/in_memory_record'

require_relative 'ccrypto/keystore'

require_relative 'ccrypto/capability'

module Ccrypto
  include TR::CondUtils

  class Error < StandardError; end
  class CcryptoProviderException < StandardError; end

  class DigestEngineException < StandardError; end
  class KDFEngineException < StandardError; end
  class HMACEngineException < StandardError; end
  class KeypairEngineException < StandardError; end
  class KeyBundleException < StandardError; end
  class X509EngineException < StandardError; end

  class X509CSRException < StandardError; end
  class X509CSRSignatureInvalid < StandardError; end

  class CipherEngineException < StandardError; end
  class ASN1EngineException < StandardError; end

  class CompressionError < StandardError; end
  class DecompressionException < StandardError; end

  class MemoryBufferException < StandardError; end

  class SecretSharingException < StandardError; end

  class X509CertException < StandardError; end
  class X509CertNotBeforeException < StandardError; end
  class X509CertNotAfterException < StandardError; end

  class KeyBundleStorageException < StandardError; end
  # Your code goes here...

  Root_OID = ["2","0","18"]

  def self.logger(tag = nil, &block)
      if @_logger.nil?
        @_logger = TeLogger::Tlogger.new
      end

     if block
      if not_empty?(tag)
        @_logger.with_tag(tag, &block)
      else
        @_logger.with_tag(@_logger.tag, &block)
      end
    else
      if is_empty?(tag)
        @_logger.tag = :CryptoJava
        @_logger
      else
        # no block but tag is given? hmm
        @_logger.tag = tag
        @_logger
      end
    end

  end

  def self.if_detail_debug(msg)
    logger.tdebug(:ccrypto_detail_debug, msg) if is_detail_debug_on?
  end

  def self.is_detail_debug_on?
    ENV['CCRYPTO_DEBUG'] == "true"
  end

end
