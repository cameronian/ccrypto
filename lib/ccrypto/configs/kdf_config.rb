

module Ccrypto
  class KDFConfig
    include AlgoConfig
    attr_accessor :algo
  end

  class ScryptConfig < KDFConfig
    attr_accessor :cost, :blocksize, :parallel
    attr_accessor :outBitLength, :salt
    
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
      @algo = :scrypt
      @cost = 16384 # 2**14
      @blocksize = 8
      @parallel = 1
      @salt = SecureRandom.random_bytes(16)
    end
  end

  class HKDFConfig < KDFConfig
    attr_accessor :salt, :digest, :outBitLength
    attr_accessor :info
    attr_accessor :provider_config
    def initialize
      @algo = :hkdf
      @salt = SecureRandom.random_bytes(16)
      @digest = :sha3_256
    end
  end # HKDFConfig

  class PBKDF2Config < KDFConfig
    attr_accessor :salt, :digest, :iter
    attr_accessor :outBitLength
    def initialize
      @algo = :pbkdf2
      @salt = SecureRandom.random_bytes(16)
      @digest = :sha3_256
      @iter = rand(300000..500000)
    end
  end # PBKDF2Config

  class Argon2Config < KDFConfig

    attr_accessor :cost, :salt, :secret, :parallel, :iter
    attr_accessor :variant
    attr_accessor :outBitLength

    def self.variants
      [:argon2d, :argon2i, :argon2id, :argon2_version_10, :argon2_version_13].freeze
    end

    def initialize

      @algo = :argon2

      # "salt" which can be stored non-secure or with the password Hash
      @salt = SecureRandom.random_bytes(16)
      
      # Secret value which has to be stored in a different secure location from the password hashes
      #@secret = SecureRandom.random_bytes(16)

      # The RFC recommends 4 GB for backend authentication and 1 GB for frontend authentication. 
      # Unit is in Kilobytes. Min is 8 kb. Convert internally to kb hence the value is 8192
      # 1024*1024 = 1048576 (1GB)
      @cost = 1048576

      # Choose the Number of CPU-Threads you can afford each call (2 Cores = 4 Threads)
      @parallel = 1

      # Set the number of Iterations each call -> More Iterations = Better Security + more Hashing Time
      # > 3 Iterations recommended
      @iter = 3

      # Follow BC library
      # Argon2d
      # Argon2i (recommended)
      # Argon2id
      # Argon2_version_10
      # Argon2_version_13
      @variant = :argon2i

    end

  end # Argon2Config

  # 
  # BCrypt returns fixed 24 bytes (192 bits) output
  #
  class BCryptConfig < KDFConfig
    # Salt is 16 bytes long
    attr_accessor :salt
    # Cost is exponent 2^cost, range from 4 - 31 inclusive
    attr_accessor :cost

    # Fixed output length of 24 bytes / 192 bits
    attr_reader :outBitLength, :max_input_byte_length
    attr_reader :salt_length, :cost_lowest_bound, :cost_upper_bound

    def self.outBitLength
      192
    end

    def self.outByteLength
      24
    end

    def self.max_input_byte_length
      72
    end

    def self.salt_length
      16
    end

    def self.cost_lowest_bound
      4
    end

    def self.cost_upper_bound
      31
    end

    def initialize
      #@salt = SecureRandom.random_bytes(16)
      @cost = 16
      @outBitLength = self.class.outBitLength
      @max_input_byte_length = self.class.max_input_byte_length # 72 # bcrypt can only handle password  <= 72 bytes (Java BC)
      @salt_length = self.class.salt_length
      @cost_lowest_bound = self.class.cost_lowest_bound
      @cost_upper_bound = self.class.cost_upper_bound
    end
  end # BCryptConfig

end
