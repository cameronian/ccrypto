

module Ccrypto
  module KeyBundle
    attr_reader :nativeKeypair

    def KeyBundle.from_storage(*args, &block)
      Provider.instance.provider.keybundle_from_storage(*args, &block)
    end

    def native
      @nativeKeypair
    end
    alias_method :keypair, :native

    private
    def method_missing(mtd, *args, &block)
      if not @nativeKeypair.nil?
        logger.debug "Sending to method #{mtd} of object '#{@nativeKeypair}' at KeyBundle level"
        @nativeKeypair.send(mtd, *args, &block)
      else
        super
      end
    end

    def logger
      Ccrypto.logger(:keybundle)
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
