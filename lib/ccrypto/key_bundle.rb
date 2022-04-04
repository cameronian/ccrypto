

module Ccrypto
  module KeyBundle
    attr_reader :nativeKeypair
  end

  module ECCKeyBundle
    include KeyBundle
  end
end
