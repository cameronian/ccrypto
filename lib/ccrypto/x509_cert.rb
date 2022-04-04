

module Ccrypto
  class X509Cert
    attr_accessor :nativeX509

    def initialize(x509)
      @nativeX509 = x509
    end

  end
end
