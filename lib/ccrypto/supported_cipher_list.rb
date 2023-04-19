
require 'yaml'
require 'fileutils'

module Ccrypto

  class SupportedCipherListError < StandardError; end

  class SupportedCipherList
    include TR::CondUtils

    def initialize(provider)
      @algos = {}
      @keysizes = {}
      @modes = {}
      @padding = {}

      @algoKeysize = {}
      @algoKeysizeMode = {}
      @algoKeysizeModePad = {}

      @keysizeMode = {}
      @algoMode = {}
      @items = []
      
      @provider = provider

    end

    def dump_to_cache(root = Dir.home)
      cacheFile = File.join(root, ".ccrypto","#{@provider.gsub(" ",".")}.cache")
      FileUtils.mkdir_p(File.dirname(cacheFile)) if not File.exist?(File.dirname(cacheFile))

      File.open(cacheFile,"w") do |f|
        f.write YAML.dump(self)
      end
    end

    def self.load_from_cache(provider, root = Dir.home)
      cacheFile = File.join(root, ".ccrypto","#{provider.gsub(" ",".")}.cache")
      if File.exist?(cacheFile)
        YAML.unsafe_load_file(cacheFile)
        #File.open(cacheFile,"r") do |f|
        #  @cont = f.read
        #end
        #if not_empty?(@cont)
        #  YAML.load(@cont)
        #else
        #  SupportedCipherList.new(provider)
        #end
      else
        SupportedCipherList.new(provider)
      end
    end

    def register(cc)
      raise SupportedCipherListError, "Ccrypto::CipherConfig required. Got '#{cc.class}'" if not cc.is_a?(Ccrypto::CipherConfig)

      @items << cc.freeze
      algo = cc.algo.to_s.downcase.to_sym
      @algos[algo] = [] if @algos[algo].nil?
      @algos[algo] << cc

      keysize = cc.keysize.to_s
      @keysizes[keysize] = [] if @keysizes[keysize].nil?
      @keysizes[keysize] << cc

      mode = cc.mode.nil? ? "" : cc.mode.to_s.downcase
      if not_empty?(mode)
        @modes[mode] = [] if @modes[mode].nil?
        @modes[mode] << cc
      end

      @algoKeysize[algo] = {  } if @algoKeysize[algo].nil?
      @algoKeysize[algo][keysize] = [] if @algoKeysize[algo][keysize].nil?
      @algoKeysize[algo][keysize] << cc

      padding = cc.padding.nil? ? "" : cc.padding.to_s

      if not_empty?(mode)
        @algoMode[algo] = {} if @algoMode[algo].nil?
        @algoMode[algo][mode] = [] if @algoMode[algo][mode].nil?
        @algoMode[algo][mode] << cc

        @keysizeMode[keysize] = {} if @keysizeMode[keysize].nil?
        @keysizeMode[keysize][mode] = [] if @keysizeMode[keysize][mode].nil?
        @keysizeMode[keysize][mode] << cc

        @algoKeysizeMode[algo] = {} if @algoKeysizeMode[algo].nil?
        @algoKeysizeMode[algo][keysize] = {} if @algoKeysizeMode[algo][keysize].nil?
        @algoKeysizeMode[algo][keysize][mode] = [] if @algoKeysizeMode[algo][keysize][mode].nil?
        @algoKeysizeMode[algo][keysize][mode] << cc

        @algoKeysizeModePad[algo] = {} if @algoKeysizeModePad[algo].nil?
        @algoKeysizeModePad[algo][keysize] = {} if @algoKeysizeModePad[algo][keysize].nil?
        @algoKeysizeModePad[algo][keysize][mode] = {} if @algoKeysizeModePad[algo][keysize][mode].nil?
        @algoKeysizeModePad[algo][keysize][mode][padding] = [] if @algoKeysizeModePad[algo][keysize][mode][padding].nil?
        @algoKeysizeModePad[algo][keysize][mode][padding] << cc
      end 

    end

    def length
      @items.length
    end

    def items
      @items.sort.freeze
    end

    def each(&block)
      @items.each(&block)
    end

    def algo_count
      @algos.length
    end
    def find_algo(algo)
      res = @algos[algo.to_s.downcase.to_sym] || []
      res.freeze
    end

    def is_list_empty?
      @algos.length == 0
    end

    # Problem with this is the algo is in symbol
    # and external app need to remember to conver it to
    # symbol in order to compare.
    # therefore the new method is_algo_supported? created
    # to solve this issue
    def algos
      @algos.keys.freeze
    end

    def is_algo_supported?(algo)
      @algos.keys.include?(algo.to_s.downcase.to_sym)
    end

    def keysizes_count
      @keysizes.length 
    end
    def keysizes
      @keysizes.keys.freeze
    end
    def find_config_by_keysize(keysize)
      @keysizes[keysize.to_s].freeze
    end

    def mode_count
      @modes.length
    end
    def find_config_by_mode(mode)
      @modes[mode.to_s].freeze
    end
    def modes
      @modes.keys.freeze
    end

    def find_algo_keysize(algo, keysize)
      if is_empty?(algo) or is_empty?(keysize)
        logger.debug "Return empty due to empty parameters"
        []
      else
        res = @algoKeysize[algo.to_s.downcase.to_sym] || {  }
        res = res[keysize.to_s] || []
        res.freeze
      end
    end

    def find_algo_mode(algo, mode)
      if is_empty?(algo) or is_empty?(mode)
        logger.debug "Return empty due to empty parameters"
        []
      else
        res = @algoMode[algo.to_s.downcase.to_sym] || {}
        res = res[mode.to_s] || []
        res.freeze
      end
    end

    def find_algo_keysize_mode(algo, keysize, mode)
      if is_empty?(algo) or is_empty?(keysize) or is_empty?(mode)
        logger.debug "Return empty due to empty parameters"
        []
      else
        res = @algoKeysizeMode[algo.to_s.downcase.to_sym] || {}
        res = res[keysize.to_s] || {}
        res = res[mode.to_s] || []
        res.freeze
      end
    end

    def find_algo_keysize_mode_padding(algo, keysize, mode, padding)
      if is_empty?(algo) or is_empty?(keysize) or is_empty?(mode) or is_empty?(padding)
        logger.debug "Return empty due to empty parameters"
        []
      else
        res = @algoKeysizeModePad[algo.to_s.downcase.to_sym] || {}
        res = res[keysize.to_s] || {}
        res = res[mode.to_s] || {}
        res = res[padding.to_s] || []
        res.freeze
      end
    end

    def find_keysize_modes(keysize, mode)
      if is_empty?(keysize) or is_empty?(mode)
        logger.debug "Return empty due to empty parameters"
        []
      else
        res = @keysizeMode[keysize.to_s] || {}
        res = res[mode.to_s] || []
        res.freeze
      end
    end

    private
    def logger
      Ccrypto.logger(:supported_cipher_list)
    end

  end
end
