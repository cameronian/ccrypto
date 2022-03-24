
require 'singleton'

module Ccrypto
  
  class ProviderException < StandardError; end

  class Provider
    include Singleton
    include TR::CondUtils

    def register(prov)
      raise ProviderException, "Provider cannot be nil" if prov.nil?
      raise ProviderException, "Provider must have name" if not prov.respond_to?(:provider_name)

      add_provider(prov)
    end

    def default_provider=(prov)
      raise ProviderException, "Nil provider is not supported" if prov.nil?

      case prov
      when String
        if is_provider_registered?(prov)
          @defaultProvider = find_provider(prov)
        else
          raise ProviderException, "Given provider '#{prov}' to set as default has yet to be registered."
        end
      else
        if prov.respond_to?(:provider_name) 
          add_provider(prov) if not is_provider_registered?(prov.provider_name)
          @defaultProvider = prov
        else
          raise ProviderException, "Given provider to set as default does not have name"
        end
      end

      @defaultProvider
    end
    def default_provider
      @defaultProvider
    end


    def find_provider(prov)
      if not_empty?(prov)
        providers[prov]
      else
        raise ProviderException, "Cannot find nil empty provider"
      end
    end

    def provider
      raise ProviderException, "No provider is registered" if is_providers_empty?
      
      if is_empty?(default_provider)
        providers.values.first
      else
        default_provider
      end
    end


    private
    def add_provider(prov)
      providers[prov.provider_name] = prov
      logger.debug "Provider '#{prov.provider_name}' registered"
    end

    def is_provider_registered?(provName)
      providers.keys.include?(provName)
    end

    def is_providers_empty?
      providers.empty?
    end

    def providers
      if @providers.nil?
        @providers = {}
      end
      @providers
    end

    def logger
      if @logger.nil?
        @logger = Tlogger.new
      end
      @logger
    end

  end
end
