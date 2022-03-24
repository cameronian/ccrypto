

module Ccrypto
  class AlgoFactory
    
    def self.engine(*args, &block)
      Provider.instance.provider.algo_instance(*args, &block)
    end

  end
end
