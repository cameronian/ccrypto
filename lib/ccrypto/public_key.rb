

module Ccrypto
  class PublicKey
    attr_accessor :native_pubKey
    def initialize(pubkey)
      @native_pubKey = pubkey
    end

    def native
      @native_pubKey
    end

    private
    def logger
      Ccrypto.logger(:pubkey)
    end

    def method_missing(mtd, *args, &block)
      if @native_pubKey.nil?
        super
      else
        logger.debug "Sending to native pubKey '#{@native_pubKey}' of method '#{mtd}'"
        @native_pubKey.send(mtd, *args, &block)
      end
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

  class CrystalDilithiumPublicKey < PublicKey; end
  class CrystalKyberPublicKey < PublicKey; end
end
