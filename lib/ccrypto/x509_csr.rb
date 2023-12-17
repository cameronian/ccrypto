

module Ccrypto
  class X509CSR
    attr_accessor :nativeCSR

    class X509CSRSignatureInvalid < StandardError; end

    def initialize(csr)
      @nativeCSR = csr
    end
  end
end
