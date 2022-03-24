

module Ccrypto
  class ASN1Object
    attr_reader :asn1_type

    def initialize(type, asn1)
      @asn1_type = type
      @asn1 = asn1
    end

    def native_asn1
      @asn1
    end

    def is_type?(type)
      @asn1_type.to_s.downcase.to_sym == type.to_s.downcase.to_sym
    end

    def method_missing(mtd, *args, &block)
      @asn1.send(mtd, *args, &block)
    end
  end
end
