

module Ccrypto
  class PrivateKey
    attr_accessor :native_privKey
    def initialize(privKey)
      @native_privKey = privKey
    end

    def method_missing(mtd, *args, &block)
      if @native_privKey.nil?
        super
      else
        @native_privKey.send(mtd, *args, &block)
      end
    end

    def respond_to_missing?(mtd, *args, &block)
      if @native_privKey.nil?
        false
      else
        @native_privKey.respond_to?(mtd)
      end
    end

  end # PrivateKey

  class ECCPrivateKey < PrivateKey; end
  class RSAPrivateKey < PrivateKey; end
  class ED25519PrivateKey < PrivateKey; end
  class X25519PrivateKey < PrivateKey; end
end
