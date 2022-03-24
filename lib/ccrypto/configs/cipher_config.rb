

module Ccrypto

  module CipherGCMMode
    attr_accessor :auth_data, :auth_tag
  end

  class CipherConfig
    include AlgoConfig
    include TR::CondUtils

    attr_accessor :algo, :key
    attr_accessor :keysize, :mode, :padding
    attr_accessor :iv, :ivLength
    attr_accessor :cipherOps

    def initialize(algo, opts = {  }, &block)
      @algo = algo

      @logger = Tlogger.new
      @logger.tag = :cipher_conf
      
      if not_empty?(opts) and opts.is_a?(Hash)
        @mode = opts[:mode]

        if is_mode?(:gcm)
          self.extend CipherGCMMode
          @logger.debug "Extending GCM mode"

          @auth_data = opts[:auth_data]
          @auth_tag = opts[:auth_tag]

          #p "auth data : #{@auth_data}"
        end

        @iv = opts[:iv] 
        @ivLength = opts[:ivLength] if is_empty?(@iv)

        @key = opts[:key]
        @keysize = opts[:keysize] if is_empty?(@key)

        @padding = opts[:padding]

        @cipherOps = opts[:cipherOps]
      end

      if block
        @mode = block.call(:mode)

        if is_mode?(:gcm)
          self.extend CipherGCMMode
          @logger.debug "Extending GCM mode"

          @auth_data = block.call(:auth_data)
          @auth_tag = block.call(:auth_tag)
        end

        @iv = block.call(:iv)
        @ivLength = block.call(:ivLength) || 16 if @iv.nil?

        @key = block.call(:key)
        @keysize = block.call(:keysize) if @key.nil?

        @padding = block.call(:padding)

        @cipherOps = block.call(:cipherOps)
      end

    end

    def has_iv?
      not_empty?(@iv)
    end

    def has_key?
      not_empty?(@key)
    end

    def is_algo?(algo)
      if @algo.nil? or is_empty?(@algo)
        false
      else
        (@algo.to_s.downcase =~ /#{algo}/) != nil
      end
    end

    def is_mode?(mode)
      if @mode.nil? or is_empty?(@mode)
        false
      else
        (@mode.to_s.downcase =~ /#{mode.to_s}/) != nil
      end
    end

    def encrypt_cipher_mode
      @cipherOps = :encrypt
    end
    def is_encrypt_cipher_mode?
      case @cipherOps
      when :encrypt, :enc
        true
      else
        false
      end
    end

    def decrypt_cipher_mode
      @cipherOps = :decrypt
    end
    def is_decrypt_cipher_mode?
      case @cipherOps
      when :decrypt, :dec
        true
      else
        false
      end
    end

    def to_s
      "#{@algo}-#{@keysize}-#{@mode}-#{@padding}"
    end

    def logger
      if @logger.nil?
        @logger = Tlogger.new
        @logger.tag = :cipher_conf
      end
      @logger
    end
  end

  class DirectCipherConfig < CipherConfig
    # str can be String or Hash
    # If String it will be directly used by underlying
    # engine with minimum parsing which means might not have other
    # info
    def initialize(str)
      raise CipherConfigException, "Hash is expected" if not str.is_a?(Hash)
      super(str[:algo], str)
    end

  end

  class CipherEngineConfig < CipherConfig
    # engine that is discovered by cipher engine
    # Means can directly use the object
  end

end
