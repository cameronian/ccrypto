

module Ccrypto

  module CipherAuthMode
    attr_accessor :auth_data, :auth_tag
  end

  class CipherConfig
    include AlgoConfig
    include TR::CondUtils

    attr_accessor :algo, :key
    attr_accessor :keysize, :mode, :padding
    attr_accessor :iv, :ivLength
    attr_accessor :cipherOps

    # required by certain mode such as CCM
    attr_accessor :plaintext_length, :ciphertext_length, :fixed_auth_tag_length

    # Use cases : 
    # openssl aes-128-xts only accepts input min 16 bytes
    # other no padding mode aes128-wrap only works on block of 8 bytes
    attr_reader :min_input_length, :mandatory_block_size

    # provider specific
    attr_accessor :native_config

    def initialize(algo, opts = {  }, &block)
      @algo = algo

      @logger = Tlogger.new
      @logger.tag = :cipher_conf

      @authMode = false
      @plaintext_length = 0
      @ciphertext_length = 0
      @min_input_length = -1
      @mandatory_Block_size = -1
      @fixed_iv_length = -1
      
      if not_empty?(opts) and opts.is_a?(Hash)
        @mode = opts[:mode]

        @authMode = opts[:authMode] || false
        #if is_mode?(:gcm)
        if @authMode
          self.extend CipherAuthMode
          @logger.debug "Extending auth mode"

          @auth_data = opts[:auth_data]
          @auth_tag = opts[:auth_tag]

        end

        @iv = opts[:iv] 
        @ivLength = opts[:ivLength] if is_empty?(@iv)

        @key = opts[:key]
        @keysize = opts[:keysize] if is_empty?(@key)

        @padding = opts[:padding]

        @cipherOps = opts[:cipherOps]

        @min_input_length = opts[:min_input_length] || -1 

        @mandatory_block_size = opts[:mandatory_block_size] || -1

        @fixed_auth_tag_length = opts[:fixed_auth_tag_length] || -1

      end

      #if block
      #  @mode = block.call(:mode)

      #  #if is_mode?(:gcm)
      #  if @authMode
      #    self.extend CipherAuthMode
      #    @logger.debug "Extending auth mode"

      #    @auth_data = block.call(:auth_data)
      #    @auth_tag = block.call(:auth_tag)
      #  end

      #  @iv = block.call(:iv)
      #  @ivLength = block.call(:ivLength) || 16 if @iv.nil?

      #  @key = block.call(:key)
      #  @keysize = block.call(:keysize) if @key.nil?

      #  @padding = block.call(:padding)

      #  @cipherOps = block.call(:cipherOps)

      #  @plaintext_length = 0
      #  @ciphertext_length = 0

      #  @min_input_length = opts[:min_input_length] || -1 

      #end

    end

    def has_iv?
      not_empty?(@iv)
    end

    def has_key?
      not_empty?(@key)
    end

    def has_min_input_length?
      not_empty?(@min_input_length) and @min_input_length.to_i > -1
    end

    def has_fixed_auth_tag_length?
      not_empty?(@fixed_auth_tag_length) and @fixed_auth_tag_length.to_i > -1
    end

    def is_auth_mode_cipher?
      @authMode == true
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
        (@mode.to_s.downcase =~ /#{mode.to_s.downcase}/) != nil
      end
    end

    def needs_plaintext_length?
      is_mode?(:ccm)
    end

    def needs_ciphertext_length?
      is_mode?(:ccm)
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
      res = [@algo, @keysize, @mode, @padding].reject { |v| is_empty?(v) }.join("-")
      "#{res} (#{@authMode})"
      #"#{@algo}-#{@keysize}-#{@mode}-#{@padding}"
    end

    def logger
      if @logger.nil?
        @logger = Tlogger.new
        @logger.tag = :cipher_conf
      end
      @logger
    end
  end

  #class DirectCipherConfig < CipherConfig
  #  # str can be String or Hash
  #  # If String it will be directly used by underlying
  #  # engine with minimum parsing which means might not have other
  #  # info
  #  def initialize(str)
  #    raise CipherConfigException, "Hash is expected" if not str.is_a?(Hash)
  #    super(str[:algo], str)
  #  end

  #end

  #class CipherEngineConfig < CipherConfig
  #  # engine that is discovered by cipher engine
  #  # Means can directly use the object
  #end

end
