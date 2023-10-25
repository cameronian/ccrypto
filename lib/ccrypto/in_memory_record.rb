
require 'yaml'
require 'fileutils'

module Ccrypto
  class InMemoryRecordError < StandardError; end

  module InMemoryRecord
    include TR::CondUtils

    module ClassMethods
      
      def record_storage_root=(val)
        @store_root
        FileUtils.mkdir_p(@store_root) if not File.exist?(@store_root)
      end

      def record_storage_root
        if @store_root.nil?
          @store_root = File.join(Dir.home,".ccrypto")
          FileUtils.mkdir_p(@store_root) if not File.exist?(@store_root)
        end
        @store_root
      end

      def load_from_storage(record, &block)
        recFile = File.join(record_storage_root, "#{record.gsub(" ","_")}.imr")
        if File.exist?(recFile)
          YAML.unsafe_load_file(recFile)
        else
          if block
            block.call(:init_new_instance)
          else
            # try to do generic
            eval("#{self.name}.new")
          end
        end
      end
      alias_method :load, :load_from_storage

    end # ClassMethods
    def self.included(klass)
      klass.extend(ClassMethods)
      @klass = klass
    end

    # 
    # Instance methods
    #
    def save_to_storage(record)
      target = File.join(self.class.record_storage_root,"#{record}.imr")  
      File.open(target,"w") do |f|
        f.write YAML.dump(self)
      end
      self
    end
    alias_method :save, :save_to_storage

    def register(obj, opts = {})
      logger.debug "Giving #{obj} to register"
      if not obj.nil?
        extrapolate(obj, opts)
        logger.debug "Extrapolated object #{obj}"
        records << obj
        logger.debug "Object #{obj} added to records"
      end
    end

    # finder only accept hash
    def find(field)
      res = []
      case field
      when Hash
        loopRes = []
        field.each do |k,v|
          case v
          when Array
            # extra configration at value is array
            # 1st parameter always the keyword to find
            ss = v.first
            fuzzy = v[1] || false
          else
            ss = v
            fuzzy = false
          end

          if not searchRes[k.to_sym].nil?
            if fuzzy
              found = searchRes[k.to_sym].select { |sk,sv|
                sk.to_s.downcase =~ /#{ss.downcase}/
              }
              loopRes = found.values
            else
              ss = ss.to_s.downcase
              if searchRes[k.to_sym].keys.include?(ss)
                loopRes = searchRes[k.to_sym][ss]
              end
            end
          end

          if is_empty?(res)
            res = loopRes
          else
            res = res & loopRes
          end
        end
      else
        raise InMemoryRecordError, "Hash is expected for finder function"
      end

      # apparantly dup and clone has some different side effects
      # dup will not copy the frozen flag but shall also ignore the dynamic method
      # created using instance_eval
      # clone shall retain the frozen flag but shall also carry over the instance_eval
      # result.
      # Hence let the application to decide to use dup or clone
      res
      #if field[:do_not_dup] == true
      #  res
      #else
      #  # always return a copy instead of actual one
      #  # dup call here might not help if there are embedded
      #  # object in the class as the dup only does swallow
      #  # copy, not deep copy
      #  # Library user need to handle deep copy
      #  res.map { |r| 
      #    if r.respond_to?(:ddup)
      #      r.ddup
      #    else
      #      r.clone
      #    end
      #  }
      #end

    end # find() operation

    def each(&block)
      raise InMemoryRecordError, "each function requires a block" if not block
      records.each(&block)
      #records.map {|r| 
      #  if r.respond_to?(:ddup)
      #    r.ddup
      #  else
      #    r.clone
      #  end
      #}.each(&block)
    end

    def collect(&block)
      records.collect(&block)
    end

    def select(&block)
      records.select(&block)
      #records.map { |r| 
      #  if r.respond_to?(:ddup)
      #    r.ddup
      #  else
      #    r.clone
      #  end
      #}.select(&block)
    end

    def empty?
      records.empty?
    end

    def to_a
      records #.freeze
      #records.map { |c| 
      #  if c.respond_to?(:ddup)
      #    c.ddup
      #  else
      #    c.clone
      #  end
      #}.freeze
    end

    private
    def records
      if @records.nil?
        @records = []
      end
      @records
    end

    def define_search_key(*args)
      args.map { |s|
        raise InMemoryRecordError, "Only support Symbol/String as search key" if not [String, Symbol].include?(s.class)
      }
      searchKeys.concat(args)
    end

    def extrapolate(a, opts = {})
      if not_empty?(opts) and not_empty?(opts[:tag_under])
        tag = opts[:tag_under]
        searchRes[tag] = {} if searchRes[tag].nil?

        val = opts[:tag_value]
        val = val.to_s.downcase

        if not_empty?(val)
          searchRes[tag][val] = [] if searchRes[tag][val].nil?
          searchRes[tag][val] << a
          logger.debug "Registering #{tag}/#{val}"

        else
          raise InMemoryRecordError, ":tag_under requires :tag_value to operate"
        end
      end # additional tagging

      searchKeys.each do |ss|
        case ss
        when Symbol, String
          val = a.send(ss)
          #logger.debug "Extrapolating #{ss} got : #{val}" 
          if not_empty?(val)
            val = val.to_s.downcase
            # search field has value
            searchRes[ss.to_sym] = {} if searchRes[ss.to_sym].nil?
            searchRes[ss.to_sym][val] = [] if searchRes[ss.to_sym][val].nil?
            searchRes[ss.to_sym][val] << a
            logger.debug "Registering #{ss.to_sym}/#{val}"
          end
        end
      end
    end

    def searchKeys
      if @searchKeys.nil?
        @searchKeys = []
      end
      @searchKeys 
    end

    def searchRes
      if @searchRes.nil?
        @searchRes = {}
      end
      @searchRes
    end

    def hash_tree
      Hash.new do |hash, key|
        hash[key] = hash_tree
      end
    end

    def logger
      Ccrypto.logger(:inMemRec)
    end


  end
end
