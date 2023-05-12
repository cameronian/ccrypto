
require_relative '../lib/ccrypto/in_memory_record'

RSpec.describe "In memory record test" do

  it 'register an object and setup the search env' do
    
    class Test
      attr_accessor :name, :contact, :phone
      def initialize(name, contact, phone)
        @name = name
        @contact = contact
        @phone = phone
      end
    end

    class TestRec
      include Ccrypto::InMemoryRecord
      def initialize
        define_search_key(:name, :contact, :phone)
      end
    end

    t = [
      Test.new("First","sanda",123),
      Test.new("Second","sanda",345),
      Test.new("Third","sanda",345),
      Test.new("Forth","hunter",345),
    ]

    ol1 = Test.new("Fifth","out of line",9393)
    ol2 = Test.new("Hua","don't think so",0)

    r = TestRec.new

    t.each do |tt|
      r.register(tt)
    end


    expect(r.find( name: "First" ).length == 1).to be true

    expect(r.find( contact: "sanda" ).length == 3).to be true
    expect(r.find( phone: 345 ).length == 3).to be true

    expect(r.find( contact: "sanda", phone: 345 ).length == 2).to be true

    expect(r.find( contact: "hunter", phone: 123 ).length == 0).to be true

    r.register(ol1, { tag_under: :jan, tag_value: "testing" })
    
    expect(r.find( jan: "testing" ).length == 1).to be true

    expect(r.find(name: ["F", true]).length == 3).to be true

    expect(r.find(name: ["th", true]).length == 3).to be true

  end

end
