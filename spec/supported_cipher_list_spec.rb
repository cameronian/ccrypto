
require_relative '../lib/ccrypto/supported_cipher_list'

RSpec.describe "Manages list of ciphers" do

  it 'keeps records of ciphers and return upon asking' do
    t = []
    inst = Ccrypto::SupportedCipherList.instance
    [:aes, :seed].each do |algo|
      [128,192,256].each do |kz|
        [:cbc, :gcm, :cfb, :ofb, :ccm].each do |mode|
          
          inst.register(Ccrypto::CipherConfig.new(algo, { keysize: kz, mode: mode }))

        end
      end
    end

    expect(inst.algo_count == 2).to be true
    expect(inst.keysizes_count == 3).to be true
    expect(inst.mode_count == 5).to be true

    res = inst.find_algo_keysize(:aes,128)
    expect(res.length == 5).to be true
    res.each do |r|
      expect(r.algo.to_sym == :aes).to be true
      expect(r.keysize.to_i == 128).to be true
    end

    res = inst.find_algo_keysize(:aes,256)
    expect(res.length == 5).to be true
    res.each do |r|
      expect(r.algo.to_sym == :aes).to be true
      expect(r.keysize.to_i == 256).to be true
    end

    res = inst.find_algo_keysize_mode(:aes,256,:gcm)
    expect(res.length == 1).to be true
    res.each do |r|
      expect(r.algo.to_sym == :aes).to be true
      expect(r.keysize.to_i == 256).to be true
      expect(r.mode.to_sym == :gcm).to be true
    end


    res = inst.find_algo(:aes)
    expect(res.length == 15).to be true
    res.each do |r|
      expect(r.algo == :aes).to be true
      puts "#{r.algo} - #{r.keysize} - #{r.mode}"
    end


    res = inst.find_keysize(128)
    expect(res.length == 10).to be true
    res.each do |r|
      expect(r.keysize.to_i == 128).to be true
      puts "#{r.algo}"
    end

    res = inst.find_mode(:ccm)
    expect(res.length == 6).to be true
    res.each do |r|
      expect(r.mode == :ccm).to be true
      puts "#{r.algo} - #{r.keysize}"
    end


  end

end
