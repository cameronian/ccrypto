

module Ccrypto

  class CipherConfig
    include AlgoConfig
    include TR::CondUtils

    # given later by the provider
    attr_accessor :ccrypto_key, :iv

    # set while this config is initialize and should not be changed
    attr_reader :algo, :padding, :mode
    attr_reader :keysize, :ivLength

    # Use cases : 
    # openssl aes-128-xts only accepts input min 16 bytes
    # other no padding mode aes128-wrap only works on block of 8 bytes
    attr_reader :min_input_length, :mandatory_block_size

    # provider specific
    attr_accessor :provider_config

    # construct a standard key config for key generation engine
    attr_accessor :key_config

    def initialize(algo, opts = {  }, &block)
      @algo = algo

      @authMode = false
      @plaintext_length = 0
      @ciphertext_length = 0
      @min_input_length = -1
      @mandatory_block_size = -1
      @fixed_iv_length = -1
      
      if not_empty?(opts) and opts.is_a?(Hash)
        @mode = opts[:mode]
        
        @authMode = opts[:authMode] || false

        @iv = opts[:iv] 
        @ivLength = opts[:ivLength] if is_empty?(@iv)

        @iv_required = (@ivLength.nil? ? false : @ivLength.to_i > 0)

        @ccrypto_key = opts[:ccrypto_key]
        @keysize = opts[:keysize] if is_empty?(@ccrypto_key)

        @padding = opts[:padding]

        @min_input_length = opts[:min_input_length] || -1 

        @mandatory_block_size = opts[:mandatory_block_size] || -1

        #@fixed_auth_tag_length = opts[:fixed_auth_tag_length] || -1

        @provider_config = opts[:provider_config]
      end

    end
    
    def iv_required?
      @iv_required
    end

    def has_iv?
      not_empty?(@iv)
    end

    def has_key?
      not_empty?(@ccrypto_key)
    end

    def has_min_input_length?
      not_empty?(@min_input_length) and @min_input_length.to_i > -1
    end

    #def has_fixed_auth_tag_length?
    #  not_empty?(@fixed_auth_tag_length) and @fixed_auth_tag_length.to_i > -1
    #end

    def has_mandatory_block_size?
      not_empty?(@mandatory_block_size) and @mandatory_block_size.to_i > -1
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
    alias_method :set_encrypt_mode, :encrypt_cipher_mode
    def is_encrypt_cipher_mode?
      @cipherOps == :encrypt
    end

    def decrypt_cipher_mode
      @cipherOps = :decrypt
    end
    alias_method :set_decrypt_mode, :decrypt_cipher_mode
    def is_decrypt_cipher_mode?
      @cipherOps == :decrypt
    end

    def to_s
      res = [@algo, @keysize, @mode, @padding].reject { |v| is_empty?(v) }.join("-")
      "#{res} (Auth mode? : #{@authMode})"
    end

    # enable sort
    def <=>(val)
      @algo <=> val.algo 
    end

    private
    def logger
      Ccrypto.logger(:cipher_conf)
    end

  end

end
