

module Ccrypto
  class UtilFactory
    def self.instance(*args, &block)
      Provider.instance.provider.util_instance(*args, &block)
    end
  end
end
