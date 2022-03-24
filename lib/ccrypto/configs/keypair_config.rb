

module Ccrypto
  class KeypairConfig
    include AlgoConfig

    attr_accessor :algo
    attr_accessor :keypair
  end

  class ECCConfig < KeypairConfig
    attr_accessor :curve
    def initialize(curve = nil)
      @algo = :ecc
      @curve = curve || :prime256v1
    end

    def to_s
      "ECC-#{@curve}"
    end
  end

end
