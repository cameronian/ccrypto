

module Ccrypto
  class SecretSharingConfig
    include AlgoConfig

    attr_accessor :split_into
    attr_accessor :required_parts

  end
end
