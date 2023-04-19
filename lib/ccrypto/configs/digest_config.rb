

module Ccrypto
  class DigestConfig
    include AlgoConfig
    include TR::CondUtils

    attr_reader :algo, :outBitLength, :outByteLength
    attr_reader :fixed_input_len_byte
    # variable allow provider to put things related to the provider e.g. JCE provider etc
    attr_accessor :provider_config
    def initialize(algo, outBitLen, opts = {  })
      @algo = algo
      @outBitLength = outBitLen
      @outByteLength = @outBitLength/8

      if not_empty?(opts)
        @provider_config = opts[:provider_config]
        @fixed_input_len_byte = opts[:fixed_input_len_byte] || -1
      else
        @provider_config = {}
        @fixed_input_len_byte = -1
      end
    end

    def has_fixed_input_len_byte?
      @fixed_input_len_byte != -1
    end

    #def to_s
    #  "Digest #{algo}"
    #end

  end

  #SHA1 = DigestConfig.new(:sha1, 160)
  #SHA224 = DigestConfig.new(:sha224, 224)
  #SHA256 = DigestConfig.new(:sha256, 256)
  #SHA384 = DigestConfig.new(:sha384, 384)
  #SHA512 = DigestConfig.new(:sha512, 512)
  #SHA512_224 = DigestConfig.new(:sha512_224, 224)
  #SHA512_256 = DigestConfig.new(:sha512_256, 256)

  #SHA3_224 = DigestConfig.new(:sha3_224, 224)
  #SHA3_256 = DigestConfig.new(:sha3_256, 256)
  #SHA3_384 = DigestConfig.new(:sha3_384, 384)
  #SHA3_512 = DigestConfig.new(:sha3_512, 512)

  #BLAKE2b160 = DigestConfig.new(:blake2b160, 160)
  #BLAKE2b256 = DigestConfig.new(:blake2b256, 256)
  #BLAKE2b384 = DigestConfig.new(:blake2b384, 384)
  #BLAKE2b512 = DigestConfig.new(:blake2b512, 512)

  #BLAKE2s128 = DigestConfig.new(:blake2s128, 128)
  #BLAKE2s160 = DigestConfig.new(:blake2s160, 160)
  #BLAKE2s224 = DigestConfig.new(:blake2s224, 224)
  #BLAKE2s256 = DigestConfig.new(:blake2s256, 256)

  #DSTU7564_256 = DigestConfig.new(:dstu7564_256, 256)
  #KUPYNA_256 = DSTU7564_256
  #DSTU7564_384 = DigestConfig.new(:dstu7564_384, 384)
  #KUPYNA_384 = DSTU7564_384
  #DSTU7564_512 = DigestConfig.new(:dstu7564_512, 512)
  #KUPYNA_512 = DSTU7564_512

  #GOSH3411 = DigestConfig.new(:gosh3411, 256)
  #GOSH3411_2012_256 = DigestConfig.new(:gosh3411_2012_256, 256) 
  #GOSH3411_2012_512 = DigestConfig.new(:gosh3411_2012_512, 512) 

  #HARAKA256 = DigestConfig.new(:haraka256, 256, { hard_in_bit_length: 256 })
  #HARAKA512 = DigestConfig.new(:haraka512, 256, { hard_in_bit_length: 512 })

  #KECCAK224 = DigestConfig.new(:keccak224, 224)
  #KECCAK256 = DigestConfig.new(:keccak256, 256)
  #KECCAK288 = DigestConfig.new(:keccak288, 288)
  #KECCAK384 = DigestConfig.new(:keccak384, 384)
  #KECCAK512 = DigestConfig.new(:keccak512, 512)

  #RIPEMD128 = DigestConfig.new(:ripemd128, 128)
  #RIPEMD160 = DigestConfig.new(:ripemd160, 160)
  #RIPEMD256 = DigestConfig.new(:ripemd256, 256)
  #RIPEMD320 = DigestConfig.new(:ripemd320, 320)

  #SHAKE128_256 = DigestConfig.new(:shake128_256, 256)
  #SHAKE256_512 = DigestConfig.new(:shake256_512, 512)
  #SHAKE128 = DigestConfig.new(:shake128, 128)
  #SHAKE256 = DigestConfig.new(:shake256, 256)

  #SKEIN1024_1024 = DigestConfig.new(:skein1024_1024, 1024)
  #SKEIN1024_384 = DigestConfig.new(:skein1024_384, 384)
  #SKEIN1024_512 = DigestConfig.new(:skein1024_512, 512)
  #
  #SKEIN256_128 = DigestConfig.new(:skein256_128, 128)
  #SKEIN256_160 = DigestConfig.new(:skein256_160, 160)
  #SKEIN256_224 = DigestConfig.new(:skein256_224, 224)
  #SKEIN256_256 = DigestConfig.new(:skein256_256, 256)

  #SKEIN512_128 = DigestConfig.new(:skein512_128, 128)
  #SKEIN512_160 = DigestConfig.new(:skein512_160, 160)
  #SKEIN512_224 = DigestConfig.new(:skein512_224, 224)
  #SKEIN512_256 = DigestConfig.new(:skein512_256, 256)
  #SKEIN512_384 = DigestConfig.new(:skein512_384, 384)
  #SKEIN512_512 = DigestConfig.new(:skein512_512, 512)

  #SM3 = DigestConfig.new(:sm3, 256)

  #WHIRLPOOL = DigestConfig.new(:whirlpool, 512)

end
