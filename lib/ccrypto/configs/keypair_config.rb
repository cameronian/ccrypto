

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

    attr_accessor :native_config 

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

    def self.name
      "Elliptic Curve (ECC)"
    end

    attr_accessor :curve
    def initialize(curve = nil, status = Algo_Active, default = false)
      @algo = :ecc
      @curve = curve || :prime256v1
      @curve = @curve.to_sym if not @curve.is_a?(Symbol)
      super(status, default)
    end

    def to_s
      "#{@curve}"
    end

    def self.supported_curves(&block)
      Provider.instance.provider.algo_instance(*[ECCConfig], &block).supported_curves
    end
  end # ECCConfig

  class RSAConfig < KeypairConfig
    def self.name
      "RSA"
    end

    attr_accessor :keysize
    def initialize(keysize = 2048, status = Algo_Active, default = false)
      @keysize = keysize
      super(status, default)
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
    def self.name
      "ED25519 (Signing Only)"
    end

    def initialize
      algo = :ed25519
      super(Algo_Active, true)
    end
  end

  # X25519 for key exchange
  class X25519Config < KeypairConfig
    def self.name
      "X25519 (Data Encipherment only)"
    end
    def initialize
      algo = :x25519
      super(Algo_Active, true)
    end
  end

end
