

module Ccrypto
  class KDFConfig
    include AlgoConfig
    attr_accessor :algo, :outBitLength 
  end

  class ScryptConfig < KDFConfig
    attr_accessor :cost, :blockSize, :parallel, :salt
    def initialize
      @cost = 16384 # 2**14
      @blockSize = 8
      @parallel = 1
      @salt = SecureRandom.random_bytes(16)
    end
  end

  class HKDFConfig < KDFConfig
    attr_accessor :salt, :info, :digest
    def initialize
      @salt = SecureRandom.random_bytes(16)
      @digest = :sha256
    end
  end
end
