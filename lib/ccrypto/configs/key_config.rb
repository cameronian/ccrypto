

module Ccrypto
  class KeyConfig
    include AlgoConfig

    attr_reader :algo, :keysize

    attr_accessor :provider_config

    def initialize(algo, keysize)
      @algo = algo
      @keysize = keysize
    end

    def to_s
      "#{@algo}/#{@keysize}"
    end

    def self.supported_secret_key_config(&block)
      Provider.instance.provider.supported_secret_key_config(&block)
    end

  end
end
