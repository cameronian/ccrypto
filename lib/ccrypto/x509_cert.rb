

module Ccrypto
  class X509Cert
    attr_accessor :nativeX509

    def initialize(x509)
      @nativeX509 = x509
    end

    def X509Cert.load_x509(*args, &block)
      Provider.instance.provider.load_x509(*args, &block)
    end


  end
end
