

module Ccrypto
  class SecretKey
    attr_accessor :algo
    attr_accessor :key

    def initialize(algo, key)
      @algo = algo
      @key = key
    end
  end
end
