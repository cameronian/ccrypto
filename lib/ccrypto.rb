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

module Ccrypto
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
    if @_clogger.nil?
      @_clogger = TeLogger::Tlogger.new
      @_clogger.tag = :ccrypto
    end

    if block
      if not_empty?(tag)
        @_clogger.with_tag(tag, &block)
      else
        @_clogger.with_tag(@_clogger.tag, &block)
      end
    else
      @_clogger
    end

  end

  def self.if_detail_debug(msg)
    logger.tdebug(:ccrypto_detail_debug, msg) if is_detail_debug_on?
  end

  def self.is_detail_debug_on?
    ENV['CCRYPTO_DEBUG'] == "true"
  end

end
