

module Ccrypto
  module KeyBundle
    attr_accessor :nativeKeypair
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
