
module Ccrypto

  class DigestMatcherError < StandardError; end

  # 
  # Match specific digest algo into common name inside the Ccrypto realm.
  # The name is essential to let program to decide what to do
  # Indirectly this should be the master list of supported digest algo
  # inside the library
  #
  class DigestMatcher
    
    MatcherTestStr = "antrapol ensures data is secure when and where you want it to be".freeze

    # 
    # Here is how the digest table value is generated
    #
    def self.generate_digest(digestConf)
      raise DigestMatcherError, "CCrypto::DigestConfig is required. Given '#{digestConf}'" if not digestConf.is_a?(Ccrypto::DigestConfig)

      dig = Ccrypto::AlgoFactory.engine(digestConf)

      if digestConf.has_fixed_input_len_byte?
        len = digestConf.fixed_input_len_byte
        if len <= MatcherTestStr.length
          dat = MatcherTestStr[0...digestConf.fixed_input_len_byte]
        else
          dat = "#{MatcherTestStr} #{MatcherTestStr[0..(len-MatcherTestStr.length)-2]}"
        end

        logger.debug "Digest #{digestConf.inspect} has fixed_input_len_byte #{digestConf.fixed_input_len_byte}. Test data length : #{dat.length}"

      else
        dat = MatcherTestStr[0...8]
        logger.debug "Digest #{digestConf.inspect} has no fixed input length restriction. Test data length : #{dat.length}"

      end

      dig.digest(dat, :b64)
    end

    def self.find_digest_key(digest)
      if @dtable.nil?
        # key is always symbol
        # Decision to use symbol instead of string is symbol has limited way to encode:
        # e.g. not able to include space or "-"
        # If use String the permutation has more combination which increase the chance of
        # ambiguity
        @dtable = {
          blake2b160: "0pLDxiKPKtVreDFhuDjDyeHwbB4=",
          blake2b256: "gNdYJkgjFG3iRHjbAh6ov3csxZnR21iPv2v2kLoQjfg=",
          blake2b384: "CbsfQsXyD35cMGZua4e6zx8BbGcSj0l56gOiiALVnKlYpCxWmpTYMjJxAmeVgjMu",
          blake2b512: "QiiQhD4DndbOlaZMczD78BAdovWG5UM3Ba4XtmiXGKVvosPFgMn3xnb5qZ0DmKCgMrCLNwNulpIZrBukfMImww==",
          blake2s128: "3jy26+gJFpYpyw1fTS6cgA==",
          blake2s160: "wTZb6KBFCN3wt21wFW8hAzs3Io0=",
          blake2s224: "+eHnZDIeFdj0VFK7OzETys8HzPzE+02DHIPI3A==",
          blake2s256: "PD5L2mMOlSI6pJHT6Va/x6EDas0vZKjWPJ2+3nE/9Jk=",
          blake3256:  "nZKbHB35VnexVgZ+6TQ2i7rDjBjy/yPPeZn2FHAvqo0=",
          dstu7564_256: "OL9g8GSInAjTmNYKwiA7wzIAq3sElpJvK7gsDcPKvz0=",
          dstu7564_384: "IS9kM7dStF5pnxTdnJHMzQzZH/RB4vtowHPzBUjpr0EYE2rFCIC+L7Iw/EUTQUDG",
          dstu7564_512: "vHf5CRg+eE9369X66djajCEvZDO3UrReaZ8U3ZyRzM0M2R/0QeL7aMBz8wVI6a9BGBNqxQiAvi+yMPxFE0FAxg==",
          gost3411: "V4SIGhgZ3iwbrELe0AtK4f0i1YWaLoiNtVXCsqEQ1Wk=",
          gost3411_2012_256: "gVQfx7U8Vd5XiKS0EjGFgbGVu0ZGj0hPRvoGz+F62FE=",
          gost3411_2012_512: "ZMzHqL34UQyUSOvJgHBYlxJg7F+nTL/Qk2BU6fmDa7l968I2D47GDVL+3aA6LG8ZCvRyLAzbh/MvsKlX833WKQ==",
          haraka256: "2pKCohySDK5bQx1G4H2C+4u8f1B09JQRnBo6f01xQHQ=",
          haraka512: "g6KV4sJyErkk+HXWdTm7PH/RruqQAwploXK6dMhHC+w=",
          keccak224: "3gFqjSP2Pc91QyH5xdaHck6aAoWnR+mjHbtFBg==",
          keccak256: "96OfrPDMlOaRrQSfgbnFzrBhTDIRu0SPqEReyblUJ4k=",
          keccak288: "v6vOPybqNq/Nmh2F675IzjWC2fjPBXl4grIb5SDKPU/uiMWj",
          keccak384: "x/pKD7QmWywC14LYltOluCDH0U74S3YZONomZlTwQep+HGud70cYOQ/7ie+sMml6",
          keccak512: "jSKQMB0fPrQV2zqYeSw59iDvwMsQwyE300dt5hNg4xPD69JP5W56v78LoV3jakJ+x4c+ZIE8NudPH5mGLo9Iag==",
          parallelhash128_256: "bfpgOoHKnrqUHTrOj0bMa6WZRTSrEYIcidQaOG//A2M=",
          parallelhash256_512: "c9DA3ooYlZNbGtxQgmfDrCltzXTmoTSmyJPO+2DrDcxcCUSodsOHctslFg/RbCVeN7LXh+sPXOd9NfRuaLPPxQ==",
          ripemd128: "icy8Y0N0gU8O87hG+MwR1Q==",
          ripemd160: "flnmtKvfan+4WH97spKi8XtAHrE=",
          ripemd256: "Mf7adgrLqqrcpxZ752ad6v6tU7prl9FnBq2TYNPPoWk=",
          ripemd320: "YdBKsjywQJ7bmByl+6Zn9J6RWAUeyeYmvSM3SoCImv028PIuHO8m3w==",
          sha1: "RwUUHm8U866yoBNfGM4V2Ad2/D4=",
          sha224: "zpQtV56miDL6LejIkXJ30o+9OtqcRsGq+EZX/A==",
          sha256: "sNTq2sf8uzHKDiUt+Y1Vr/HVrW8AgLevQZ/HHKJubDA=",
          sha384: "5KqG3DsSm6KxmAeS+buH0avldfM2DcR1b9GMRZjlK1F5jR5Lwg0TGbRRJ5U3ylFB",
          sha512: "T7J7I3/VFMRSKt8q8KrWi9fsnzjXpFNEvoL5eVGI1Vt0HHfmFH5SHNg6L4X3l5GBcg6X6zlUBSqZk1QiKy8b4g==",
          sha512_224: "On15IMF7xtTypEN2zlbl9LMD0++AX7Vo0uEGGw==",
          sha512_256: "t1xIQgjCiIapNoseg1q3DdQQO7rngCga9ewqZ44EqOg=",
          sha3_224: "VjXrA6pwc0z7BFPaGFCLGWB6o5LaOKAw8XGs1A==",
          sha3_256: "raUIZ+3KcfEJTtcCzQCSTmZPcZFhlOVUsjDghhfhPxo=",
          sha3_384: "wiBHqnLyOzMl228JaQq8Zd5E9GFJQlY3lWIE/14AyQbY0csl3wUPoqmIFEBJ5EVz",
          sha3_512: "5fNjwalHgZL2ROHQNtsdJhVIkrXOXCOfTZg0kNXGuGrDVCwl9ERVAG5wHNXKDFW/D72gqoW0XDUIwDt+DMyzyw==",
          shake128_256: "ChxTTokFs354PoInE4eXcZU3RLslAjBAgogFUlZKAr8=",
          shake256_512: "1c+ERFraWmph91mdDe7LEpmcjgl3fYocO4a5L09DBM7BsuUMrgXC/QOwW9Ug6U7bqzpLa2Wot9K1ilEhy9lsUw==",
          skein1024_1024: "LSCcR3WLi7KbAn30M8xDbZVn/DA0UJcJj4PrO/IH1nwFJ3Hac9v5XC1ckHvUzmQeaygzV1yyDbqnvmnhFx8WWRNhJ6/9doUHt5pPdH9czupjV1F1J0CrjFbgnQaruyAEWPJ/roOpWR28sVohAiXlZT73/jvFA1qUn46kFr1KOFo=",
          skein1024_384: "py97erCjOPwWNv4kE7KoV5op22Lkh0xq/JM5hw6ezu2+5Vm9ylvCgESbCFrgn+uy",
          skein1024_512: "OnAy/fSXBykZpAFSkqfmRFPtiFe2SpEeGH8JVY1jhllbhOqGyLyL+flY9Buymc8O+bkRM95IZphkwgD1R5nlmw==",
          skein256_128: "2IzEhmqfdrBzNJli8v9tHA==",
          skein256_160: "mBFGB+cBumPVLdjNHg06szlvwNo=",
          skein256_224: "ZG8Ia4m2/8W2+zI76zpensT84xYjZZeQBNmCOw==",
          skein256_256: "s3hhdiS2r+nTJxE2f0Vkx0MvDvPc9j35zbXbziDkovM=",
          skein512_128: "bb17DoKVvzqyA4IconI3vg==",
          skein512_160: "BzoVjJObMVkGMx+sa7uLS/kNCIk=",
          skein512_224: "LlxCIHa9sHm+g7wXTOesVpjSrk7TvOYMC5AknQ==",
          skein512_256: "4UUxlYOSqITg96ZtlBYBUtQeh1mLgOuoMFP47SmJ4RA=",
          skein512_384: "EDoBTYO6G2mbBCfYuan1lIuazB+ToGP4gUB8uj+248SUd0r57tY1mWEfOMQOoSiS",
          skein512_512: "94/CDISu4nyY2Pobuq9N5lGA0Jdybc3gfdudSmUbuHdXYdjnameJt9UvunQIO9MCufG0QyEgOBsjBNasPw46XQ==",
          sm3: "X1mEgSOAmjzrvU5jci1e2iK42HVyYvROhpxp0BiKw2s=",
          tiger: "Y5UJEZq2ZEFkoOFSak1WmRcstCFuRe9H",
          tuplehash128_256: "xTUUf5y3DDNvfYEY19ezdXygpzcx33nnpexAzU81HR4=",
          tuplehash256_512: "Ey2RfbNNCYMu9CpmEwNq+BMrd90TPCCPV1fgefGdY9bNObnb76l+z+ju3ZPZ12+eGAz3xTXAX7HKOWqrw/8r2w==",
          whirlpool: "CsHu74qufeIg1eG72WDiydOO+CkPg5XDIzMFL4izDmFg+YHWE/v1g/RYzTD3BipFUWrrHKz+1itoYTxuJ4w+Mg=="            
        }
      end

      @dtable.invert[digest]
    end

    private
    def self.logger
      Ccrypto.logger(:digest_matcher)
    end

  end
end
