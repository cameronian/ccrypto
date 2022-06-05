

module Ccrypto
  class PKCS7Config
    include AlgoConfig
    include TR::CondUtils

    #attr_accessor :keybundle

    attr_accessor :private_key, :public_key
    # for signing operation
    attr_accessor :signerCert
    # for decryption operation
    attr_accessor :certForDecryption

    def add_recipient_cert(cert)
      recpCerts << cert if not_empty?(cert)
    end

    def recipient_certs
      recpCerts
    end

    protected
    def recpCerts
      if @recpCerts.nil?
        @recpCerts = []
      end
      @recpCerts
    end
  end
end
