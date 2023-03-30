

module Ccrypto
  class KeyConfig
    include AlgoConfig

    attr_accessor :algo, :keysize

    def to_s
      "#{@algo}/#{@keysize}"
    end

    def self.supported_secret_key_config(&block)
      Provider.instance.provider.supported_secret_key_config(&block)
    end

  end
end
