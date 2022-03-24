

module Ccrypto
  module AlgoConfig
   
    module ClassMethods

    end
    def self.include(klass)
      klass.extend(ClassMethods)
    end

    attr_accessor :provider_config
    def provider_info(val)
      @provider_config = val
      self
    end

  end
end
