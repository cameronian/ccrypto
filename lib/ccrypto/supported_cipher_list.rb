
require 'singleton'

module Ccrypto

  class SupportedCipherListError < StandardError; end

  class SupportedCipherList
    include TR::CondUtils
    include Singleton

    include TeLogger::TeLogHelper
    teLogger_tag :supCipherList

    def initialize
      @algos = {}
      @keysizes = {}
      @modes = {}

      @algoKeysize = {}
      @algoKeysizeMode = {}
      @keysizeMode = {}
      @algoMode = {}
      @items = []
    end

    def register(cc)
      raise SupportedCipherListError, "Ccrypto::CipherConfig required. Got '#{cc.class}'" if not cc.is_a?(Ccrypto::CipherConfig)

      @items << cc
      algo = cc.algo.to_sym
      @algos[algo] = [] if @algos[algo].nil?
      @algos[algo] << cc

      keysize = cc.keysize.to_s
      @keysizes[keysize] = [] if @keysizes[keysize].nil?
      @keysizes[keysize] << cc

      mode = cc.mode.nil? ? "" : cc.mode.to_s
      if not_empty?(mode)
        @modes[mode.to_s] = [] if @modes[mode.to_s].nil?
        @modes[mode.to_s] << cc
      end

      @algoKeysize[algo] = {  } if @algoKeysize[algo].nil?
      @algoKeysize[algo][keysize] = [] if @algoKeysize[algo][keysize].nil?
      @algoKeysize[algo][keysize] << cc

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
      end 

    end

    def items
      @items
    end

    def each(&block)
      @items.each(&block)
    end

    def algo_count
      @algos.length
    end
    def find_algo(algo)
      @algos[algo.to_sym] || []
    end
    def algos
      @algos.keys
    end

    def keysizes_count
      @keysizes.length 
    end
    def keysizes
      @keysizes.keys
    end
    def find_keysize(keysize)
      @keysizes[keysize.to_s]
    end

    def mode_count
      @modes.length
    end
    def find_mode(mode)
      @modes[mode.to_s]
    end
    def modes
      @modes.keys
    end

    def find_algo_keysize(algo, keysize)
      res = @algoKeysize[algo.to_sym] || {  }
      res[keysize.to_s] || []
    end

    def find_algo_mode(algo, mode)
      res = @algoMode[algo.to_sym] || {}
      res[mode.to_s] || []
    end

    def find_algo_keysize_mode(algo, keysize, mode)
      res = @algoKeysizeMode[algo.to_sym] || {}
      res = res[keysize.to_s] || {}
      res[mode.to_s] || []
    end

    def find_keysize_modes(keysize, mode)

      res = @keysizeMode[keysize.to_s] || {}
      res[mode.to_s] || []
    end

  end
end
