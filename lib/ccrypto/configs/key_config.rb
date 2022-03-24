

module Ccrypto
  class KeyConfig
    include AlgoConfig

    attr_accessor :algo, :keysize

    def to_s
      "#{@algo}/#{@keysize}"
    end

  end
end
