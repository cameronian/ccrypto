

module Ccrypto
  class HMACConfig
    include AlgoConfig

    attr_accessor :key, :digest

    def initialize
      @digest = :sha256
    end
  end
end
