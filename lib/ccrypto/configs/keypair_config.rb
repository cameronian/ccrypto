

module Ccrypto
  class KeypairConfig
    include AlgoConfig

    attr_accessor :algo
    attr_accessor :keypair, :private_key, :public_key

    def has_keypair?
      (not @keypair.nil?) or not (@privateKey.nil? and @publicKey.nil?)
    end

    def has_private_key?
      if has_keypair?
        not @keypair.private_key.nil?
      else
        not @private_key.nil?
      end
    end

    def has_public_key?
      if has_keypair?
        not @keypair.public_key.nil?
      else
        not @public_key.nil?
      end
    end
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

  class RSAConfig < KeypairConfig
    attr_accessor :keysize
    def initialize(keysize = 2048)
      @keysize = keysize
    end

    def to_s
      "RSA-#{keysize} bits"
    end
  end

end
