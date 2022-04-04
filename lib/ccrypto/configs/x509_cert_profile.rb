

module Ccrypto
  module X509
    class CertProfile
      include Ccrypto::AlgoConfig

      attr_accessor :owner_name, :org
      attr_accessor :org_unit, :email, :dns_name, :ip_addr, :uri
      attr_accessor :public_key, :serial, :not_before, :not_after
      attr_accessor :subj_key_id, :auth_key_id
      attr_accessor :crl_dist_point, :ocsp_url
      attr_accessor :issuer_cert
      attr_accessor :hashAlgo

      def initialize
        @hashAlgo = Ccrypto::SHA256
        @serial = SecureRandom.hex(16)
        @subj_key_id = true
        @auth_key_id = true
        @issuerCert = false
        now = Time.now
        @not_before = Time.new(now.year, now.month, now.day)
        @not_after = Time.new(now.year+2, now.month, now.day)
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
      

      class KeyUsage
        Key = [:digitalSignature, :nonRepudiation, :keyEncipherment, :dataEncipherment, :keyAgreement, :keyCertSign, :crlSign, :encipherOnly, :decipherOnly]

        def initialize
          @selected = []
        end

        def selected
          @selected 
        end

        Key.each do |k|
          class_eval <<-END
            def enable_#{k}
              @selected << :#{k}
              self
            end
          END
        end

      end  # KeyUsage


      class ExtKeyUsage
        Key = [:allPurpose, :serverAuth, :clientAuth, :codeSigning, :emailProtection, :timestamping, :ocspSigning, :ipSecIKE, :msCodeInd, :msCodeCom, :msCtlsign, :msEFS, :dvcs]

        def initialize
          @selected = []
        end

        def selected
          @selected 
        end

        Key.each do |k|
          class_eval <<-END
            def enable_#{k}
              @selected << :#{k}
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

    end
  end
end
