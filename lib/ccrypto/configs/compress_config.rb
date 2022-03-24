

module Ccrypto
  class CompressionConfig
    include AlgoConfig

    attr_accessor :level, :strategy

    def initialize
      @level = :default
      @strategy = :default
    end

  end
end
