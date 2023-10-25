

module Ccrypto
  module Keystore

    class KeystoreException < StandardError; end
   
    def Keystore.load_keystore(*args, &block)
      Provider.instance.provider.load_keystore(*args, &block)
    end

    def Keystore.load_keystore_file(*args, &block)
      Provider.instance.provider.load_keystore_file(*args, &block)
    end

    def Keystore.convert_keystore(*args, &block)
      Provider.instance.provider.convert_keystore(*args, &block)
    end

    def Keystore.convert_keystore_file(*args, &block)
      Provider.instance.provider.convert_keystore_file(*args, &block)
    end

  end
end
