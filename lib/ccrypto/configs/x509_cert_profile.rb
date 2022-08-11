
require 'active_support'
require 'active_support/core_ext/time'

module Ccrypto
  module X509
    class CertProfile
      include Ccrypto::AlgoConfig
      include TR::CondUtils

      include TeLogger::TeLogHelper
      teLogger_tag :cert_prof

      class CertProfileException < StandardError; end

      attr_accessor :owner_name, :org
      attr_accessor :org_unit, :email, :dns_name, :ip_addr, :uri
      attr_accessor :public_key, :serial, :not_before, :not_after
      attr_accessor :subj_key_id, :auth_key_id
      attr_accessor :crl_dist_point, :ocsp_url, :issuer_url
      attr_accessor :issuer_cert
      attr_accessor :hashAlgo
      attr_accessor :raise_if_validity_date_not_in_issuer_range

      def initialize
        @hashAlgo = Ccrypto::SHA256
        @serial = SecureRandom.hex(16)
        @subj_key_id = true
        @auth_key_id = true
        @issuerCert = false
        now = Time.now
        @not_before = Time.new(now.year, now.month, now.day)
        @not_after = Time.new(now.year+2, now.month, now.day)
        @raise_if_validity_date_not_in_issuer_range = false
      end

      def gen_issuer_cert?
        @issuerCert
      end
      def gen_issuer_cert=(val)
        @issuerCert = val
      end

      def gen_subj_key_id?
        @subj_key_id
      end
      def gen_subj_key_id=(val)
        @subj_key_id = val
      end

      def gen_auth_key_id?
        @auth_key_id
      end
      def gen_auth_key_id=(val)
        @auth_key_id = val
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

      def email
        if @email.nil?
          []
        elsif not @email.is_a?(Array)
          [@email]
        else
          @email
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

      def ip_addr
        if @ip_addr.nil?
          []
        elsif not @ip_addr.is_a?(Array)
          [@ip_addr]
        else
          @ip_addr
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

      def crl_dist_point
        if @crl_dist_point.nil?
          []
        elsif not @crl_dist_point.is_a?(Array)
          [@crl_dist_point]
        else
          @crl_dist_point
        end
      end

      def ocsp_url
        if @ocsp_url.nil?
          []
        elsif not @ocsp_url.is_a?(Array)
          [@ocsp_url]
        else
          @ocsp_url
        end
      end

      def issuer_url
        if @issuer_url.nil?
          []
        elsif not @issuer_url.is_a?(Array)
          [@issuer_url]
        else
          @issuer_url
        end
      end

      def validity(qty, unit = :years)
     
        raise CertProfileException, "not_before has to set before validity can be set" if is_empty?(@not_before)

        case unit
        when :days, :day
          adv = { days: qty }
        when :months, :month
          adv = { months: qty }
        when :weeks, :week
          adv = { weeks: qty }
        when :years, :year
          adv = { years: qty }
        else
          raise CertProfileException, "Unknown unit '#{unit}'"
        end

        @not_after = @not_before.advance(adv)

      end

      def match_issuer_not_before(issuer_not_before)
        if not_empty?(issuer_not_before)
          if issuer_not_before.is_a?(Time)
            if issuer_not_before > @not_before
              if @raise_if_validity_date_not_in_issuer_range
                raise X509CertNotBeforeException, "Issuer not_before '#{issuer_not_before.localtime}' > To-be-signed cert not_before '#{@not_before.localtime}'"
              else
                teLogger.info "Issuer has not_before at #{issuer_not_before.localtime} but to-be-signed certificate has not_before at #{@not_before.localtime}. To-be-signed certificate cannot has not_before earlier than issuer not_before. Auto adjusting the to-be-signed certificate to #{issuer_not_before.localtime}."
                @not_before = issuer_not_before
              end
            else
              teLogger.debug "to-be-signed certificate has valid not_before value (#{@not_before}) : after issuer not_before (#{issuer_not_before})"
            end
          else
            teLogger.warn "issuer_not_before is not a Time object. It is a '#{issuer_not_before.class}'"
          end
        end
      end

      def match_issuer_not_after(issuer_not_after)
        if not_empty?(issuer_not_after)
          if issuer_not_after.is_a?(Time)
            if @not_after > issuer_not_after
              if @raise_if_validity_date_not_in_issuer_range
                raise X509CertNotAfterException, "Issuer not_after '#{issuer_not_after.localtime}' < To-be-signed cert not_after '#{@not_after.localtime}'"
              else
                teLogger.info "Issuer has not_after at #{issuer_not_after.localtime} but to-be-signed certificate has not_after at #{@not_after.localtime}. To-be-signed certificate cannot has not_after later than issuer not_after. Auto adjusting the to-be-signed certificate to #{issuer_not_after.localtime}."
                @not_after = issuer_not_after
              end
            else
              teLogger.debug "to-be-signed certificate has valid not_after value (#{@not_after}): before issuer not_after (#{issuer_not_after})"
            end
          else
            teLogger.warn "issuer_not_after is not a Time object. It is a '#{issuer_not_after.class}'"
          end
        end
      end

      class KeyUsage
        #Key = [:digitalSignature, :nonRepudiation, :keyEncipherment, :dataEncipherment, :keyAgreement, :keyCertSign, :crlSign, :encipherOnly, :decipherOnly]
        Usages = {
          digitalSignature: "Digital signature",
          nonRepudiation: "Non Repudiation",
          keyEncipherment: "Key encipherment",
          dataEncipherment: "Data encipherment",
          keyAgreement: "Key agreement",
          keyCertSign: "Sign/Issue certificate",
          crlSign: "Sign/Issue Certificate Revocation List (CRL)",
          encipherOnly: "Data encipherment only",
          decipherOnly: "Data decipherment only",
        }

        def initialize
          @selected = {  }
        end

        def selected
          @selected 
        end

        Usages.keys.each do |k|
          class_eval <<-END
            def enable_#{k}(critical = false)
              @selected[:#{k}] = critical
              self
            end
          END
        end

      end  # KeyUsage


      class ExtKeyUsage
        #Key = [:allPurpose, :serverAuth, :clientAuth, :codeSigning, :emailProtection, :timestamping, :ocspSigning, :ipSecIKE, :msCodeInd, :msCodeCom, :msCtlsign, :msEFS, :dvcs]
        Usages = {
          allPurpose: "All extended key usages",
          serverAuth: "TLS server authentication",
          clientAuth: "TLS client authentication",
          codeSigning: "Code signing",
          emailProtection: "Email protection",
          timestamping: "Time stamping",
          ocspSigning: "Online Cert Status Protocol signing",
          ipSecIKE: "IPSec Initial Key Exchange",
          msCodeInd: "Microsoft Code Ind",
          msCodeCom: "Microsoft Code Com",
          msCtlsign: "Microsoft CTL Sign",
          msEFS: "Microsoft EFS",
          dvcs: "DVCS purposes"
        }


        def initialize
          @selected = {  }
        end

        def selected
          @selected 
        end

        Usages.keys.each do |k|
          class_eval <<-END
            def enable_#{k}(critical = false)
              @selected[:#{k}] = critical
              self
            end
          END
        end

        
      end  #extKeyUsage

      def key_usage
        if @keyUsage.nil?
          @keyUsage = KeyUsage.new
        end
        @keyUsage
      end

      def ext_key_usage
        if @extKeyUsage.nil?
          @extKeyUsage = ExtKeyUsage.new
        end
        @extKeyUsage
      end

      def add_domain_key_usage(oid, critical = false)
        domain_key_usage[oid] = critical
      end

      def domain_key_usage
        if @domainKeyUsage.nil?
          @domainKeyUsage = {  }
        end
        @domainKeyUsage
      end

    end
  end
end
