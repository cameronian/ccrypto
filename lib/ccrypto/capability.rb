

module Ccrypto
  module Capability

    def self.supported_keypair_config(*args,&block)
      Provider.instance.provider.supported_keypair_config(*args, &block)
    end

    def self.supported_secret_key_config(*args, &block)
      Provider.instance.provider.supported_secret_key_config(*args, &block)
    end

  end
end
