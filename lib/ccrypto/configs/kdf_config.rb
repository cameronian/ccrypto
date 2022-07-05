

module Ccrypto
  class KDFConfig
    include AlgoConfig
    attr_accessor :algo, :outBitLength 
  end

  class ScryptConfig < KDFConfig
    attr_accessor :cost, :blockSize, :parallel, :salt
    
    # https://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors
    # Specific good explanation:
    # https://stackoverflow.com/a/30308723/3625825
    # Memory requirement : 128 bytes x Cost Factor x block size
    # at cost factor 2^14 = 16384 == 128 bytes x 16384 (cost) x 8 (block size) === 16 MB 
    # if at cost factor 2 ^ 14 = 16384 == 128 x 16384 (cost) x 512 (block size) === 1 GB 
    # Tuning the cost & block size can change how much memory needed to process this
    # for EACH TIME PROCESSING...
    # 
    # Legitimate user only need to do once
    # Attacker using brute force may not be feasiable anymore if the value is high
    #
    # BC source code indicated 
    # Cost parameter bound  >= 1 and < 65536 (2^16) (value must be power of 2, i.e 2^1 = 2, 2^2 = 4 etc)
    # the actual is the max value should be 2^(128*blocksize/8)
    # block size = 1 == 2^(128*1/8) == 2^(128/8) == 2^16
    # block size = 2 == 2^(128*2/8) == 2^32 == 4 GB
    # If want higher value, change block size 2^16 is min in this case because block must be 1 and above
    # block size>= 1
    # parallelization must be > 1 and < Integer.MAX_VALUE / (128 * parallelization * 8)
    # tested on Java 8 Integer.MAX_VALUE = 2GB (2^31)
    # if parallelization value == 1, the supported parallel is 2048,000
    # Hmm that's why I think nobody use more then 1?
    #
    # this config shall be 16 MB per process
    #costParam = opts[:costParam] || 2 ** 14 # 2 ^ 16
    #blockSize = opts[:blockSize] || 8
    # this one also 16 MB per process
    # but apparently there are saying higher r is better 
    # https://stackoverflow.com/a/33297994/3625825

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

  class PBKDF2Config < KDFConfig
    attr_accessor :salt, :digest, :iter
    def initialize
      @salt = SecureRandom.random_bytes(16)
      @digest = :sha256
      @iter = rand(200000..400000)
    end
  end
end
