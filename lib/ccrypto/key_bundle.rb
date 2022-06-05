

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
end
