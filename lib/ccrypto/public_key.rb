

module Ccrypto
  class PublicKey
    attr_accessor :native_pubKey
    def initialize(pubkey)
      @native_pubKey = pubkey
    end
  end

  class ECCPublicKey < PublicKey
  end
end
