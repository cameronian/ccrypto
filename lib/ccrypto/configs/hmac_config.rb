

module Ccrypto
  class HMACConfig
    include AlgoConfig

    attr_accessor :ccrypto_key

    attr_reader :digest_config

    attr_accessor :provider_config

    def initialize(digestConfig)
      @digest_config = digestConfig
    end

  end
end
