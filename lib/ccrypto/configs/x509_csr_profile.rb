
require_relative 'algo_config'

module Ccrypto
  module X509
    class CSRProfile
      include Ccrypto::AlgoConfig
      include TR::CondUtils

      include TeLogger::TeLogHelper
      teLogger_tag :csr

      attr_accessor :owner_name, :org
      attr_accessor :org_unit, :email, :dns_name, :ip_addr, :uri
      attr_accessor :public_key
      attr_accessor :hashAlgo

      def initialize
        @hashAlgo = :sha256
      end

      def org_unit
        if @org_unit.nil?
          []
        elsif not @org_unit.is_a?(Array)
          [@org_unit]
        else
          @org_unit
        end
      end

      def email=(val)
        if @email.nil?
          @email = []
        end

        case val
        when Array
          @email += val
        else
          @email << val
        end
      end
      def email
        if @email.nil?
          []
        elsif not @email.is_a?(Array)
          [@email]
        else
          @email
        end
      end

      def dns_name=(val)
        if @dns_name.nil?
          @dns_name = []
        end

        case val
        when Array
          @dns_name += val
        else
          @dns_name << val
        end
      end

      def dns_name
        if @dns_name.nil?
          []
        elsif not @dns_name.is_a?(Array)
          [@dns_name]
        else
          @dns_name
        end
      end


      def ip_addr=(val)
        if @ip_addr.nil?
          @ip_addr = []
        end

        case val
        when Array
          @ip_addr += val
        else
          @ip_addr << val
        end
      end
      def ip_addr
        if @ip_addr.nil?
          []
        elsif not @ip_addr.is_a?(Array)
          [@ip_addr]
        else
          @ip_addr
        end
      end

      def uri=(val)
        if @uri.nil?
          @uri = []
        end

        case val
        when Array
          @uri += val
        else
          @uri << val
        end
      end

      def uri
        if @uri.nil?
          []
        elsif not @uri.is_a?(Array)
          [@uri]
        else
          @uri
        end
      end

      def add_custom_attribute(key,value, type = :string)
        additional_attributes[key] = { value: value, type: type }
      end

      def additional_attributes
        if @addAttr.nil?
          @addAttr = {}
        end
        @addAttr
      end

      def add_custom_extension(oid, value, type = :string, critical = false)
        custom_extension[oid] = { type: type, value: value, critical: critical }
      end

      def custom_extension
        if @custom_extension.nil?
          @custom_extension = {  }
        end
        @custom_extension
      end

    end
  end
end
