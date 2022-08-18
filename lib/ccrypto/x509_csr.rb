

module Ccrypto
  class X509CSR
    attr_accessor :nativeCSR

    def initialize(csr)
      @nativeCSR = csr
    end
  end
end
