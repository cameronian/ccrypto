

module Ccrypto
  module KeyBundle
    attr_reader :nativeKeypair

    def KeyBundle.from_storage(*args, &block)
      Provider.instance.provider.keybundle_from_storage(*args, &block)
    end

    def native
      @nativeKeypair
    end

  end

  module ECCKeyBundle
    include KeyBundle
  end

  module RSAKeyBundle
    include KeyBundle
  end

  module ED25519KeyBundle
    include KeyBundle
  end

  module X25519KeyBundle
    include KeyBundle
  end
end
