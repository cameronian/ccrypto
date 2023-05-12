
require 'yaml'
require 'fileutils'

require_relative 'in_memory_record'

module Ccrypto

  class SupportedCipherListError < StandardError; end

  class SupportedCipherList
    include TR::CondUtils
    include InMemoryRecord

    def initialize
      define_search_key(:algo, :keysize, :mode, :padding, :ivLength)
    end

  end
end
