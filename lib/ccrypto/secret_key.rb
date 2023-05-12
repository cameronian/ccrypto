

module Ccrypto
  class SecretKey
    attr_reader :algo, :keysize

    attr_reader :native_key

    attr_accessor :provider_config

    def initialize(algo, keysize, key)
      @algo = algo
      @keysize = keysize
      @native_key = key
    end

  end
end
