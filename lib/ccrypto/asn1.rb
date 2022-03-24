

module Ccrypto
  class ASN1

    def self.engine(*args, &block)
      Provider.instance.provider.asn1_engine(*args, &block) 
    end

  end
end
