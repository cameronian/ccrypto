

module Ccrypto

  class KeypairConfig
    include AlgoConfig

    attr_accessor :algo
    attr_accessor :keypair, :private_key, :public_key
    
    attr_reader :algo_status

    Algo_Active = :active
    Algo_NotRecommended = :not_recommended
    Algo_Obsolete = :obsolete
    Algo_Broken = :broken

    attr_reader :default

    attr_accessor :provider_config 

    def initialize(status = Algo_Active, default = false)
      @algo_status = status
      @default = default
    end

    def is_default_algo?
      @default
    end

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

    def self.keypair_purposes
      {
        signing: "Keypair for signing and digital signature operation",
        cipher: "Keypair for data encryption operation",
        sign_and_encrypt: "Keypair for both signing and data encryption operation"
      }
    end

    def self.supported_keypair_config(purpose = :signing, &block)
      Provider.instance.provider.supported_keypair_config(purpose, &block)
    end

  end # KeypairConfig

  class ECCConfig < KeypairConfig

    def self.algo_name
      "Elliptic Curve (ECC) (Classical - Signing and Encryption)"
    end

    def self.algo_key
      :ecc
    end

    attr_reader :curve
    def initialize(curve = nil, status = Algo_Active, default = false)
      @algo = self.class.algo_key
      @curve = curve || :prime256v1
      @curve = @curve.to_sym if not @curve.is_a?(Symbol)
      super(status, default)
    end

    def param
      @curve
    end

    def to_s
      "ECC - #{@curve}"
    end

    def self.supported_curves(&block)
      Provider.instance.provider.algo_instance(*[ECCConfig], &block).supported_curves
    end
  end # ECCConfig

  class RSAConfig < KeypairConfig
    def self.algo_name
      "RSA (Classical - Signing and Encryption)"
    end

    def self.algo_key
      :rsa
    end

    attr_reader :keysize
    def initialize(keysize = 2048, status = Algo_Active, default = false)
      @algo = self.class.algo_key
      @keysize = keysize
      super(status, default)
    end

    def param
      @keysize
    end

    def to_s
      "RSA-#{keysize} bits"
    end

    def self.supported_keysizes(&block)
      Provider.instance.provider.algo_instance(*[RSAConfig],&block).supported_keysizes
    end
  end # RSAConfig

  # ED25519 for data signature
  class ED25519Config < KeypairConfig
    def self.algo_name
      "ED25519 (Classical - Signing Only)"
    end

    def self.algo_key
      :ed25519
    end

    def initialize
      @algo = self.class.algo_key
      super(Algo_Active, true)
    end

    def param
      nil
    end
  end

  # X25519 for key exchange
  class X25519Config < KeypairConfig
    def self.algo_name
      "X25519 (Data Encipherment only)"
    end

    def self.algo_key
      :x25519
    end

    def initialize
      @algo = self.class.algo_key
      super(Algo_Active, true)
    end
    
    def param
      nil
    end
  end

  # PQ Crystal Kyber
  class CrystalKyberConfig < KeypairConfig
    def self.algo_name
      "Crystal Kyber (PQC - Signing)"
    end
    def self.algo_key
      :crystal_kyber
    end

    attr_reader :param
    def initialize(kyberParam, default = false)
      @param = kyberParam
      @algo = self.class.algo_key
      super(Algo_Active, default)
    end

    def to_s
      "PQ Crystal Kyber #{@param}"
    end
  end

  # PQ Crystal Dlithium
  class CrystalDilithiumConfig < KeypairConfig
    # has unintended consequences during YAML dump and load
    #def self.name
    #  "PQ Crystal Dilithium Family (for Signing)"
    #end
    def self.algo_name
      "Crystal Dilithium (PQC - Encryption)"
    end
    def self.algo_key
      :crystal_dilithium
    end
    attr_reader :param
    def initialize(param, default = false)
      @param = param
      @algo = self.class.algo_key
      super(Algo_Active, default)
    end

    def to_s
      "PQ Crystal Dilithium #{@param}"
    end
  end

end
