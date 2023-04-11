

module Ccrypto
  class PublicKey
    attr_accessor :native_pubKey
    def initialize(pubkey)
      @native_pubKey = pubkey
    end

    def method_missing(mtd, *args, &block)
      if @native_pubKey.nil?
        super
      else
        @native_pubKey.send(mtd, *args, &block)
      end
    end

    def native
      @native_pubKey
    end

    def respond_to_missing?(mtd, *args, &block)
      if @native_pubKey.nil?
        false
      else
        @native_pubKey.respond_to?(mtd)
      end
    end

  end # PublicKey

  class ECCPublicKey < PublicKey; end
  class RSAPublicKey < PublicKey; end
  class ED25519PublicKey < PublicKey; end
  class X25519PublicKey < PublicKey; end
end
