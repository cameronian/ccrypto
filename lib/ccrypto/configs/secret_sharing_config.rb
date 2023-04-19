

module Ccrypto
  class SecretSharingConfig
    include AlgoConfig

    attr_accessor :split_into
    attr_accessor :required_parts

    def initialize(val = {})
      if val.is_a?(Hash) 
        @split_into = val[:split_into]
        @required_parts = val[:required_parts]
      end
    end

  end
end
