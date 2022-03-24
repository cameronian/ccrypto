# Ccrypto

Ccrypto - Common Crypto is the attempt to normalize cryptography API between Ruby and Java, and possibly other runtime supported by Ruby.

It is rooted in Ruby because of its expressiveness.

This gem is mainly provide high level common elements for the implemented runtime to select a proper implementation.

This including all the classes under the configs/ directory. Those are suppose to be parameter pass to the runtime implementation to pick the required implementation under that runtime.


## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ccrypto'

# select runtime
# if Ruby runtime backed by OpenSSL
# https://github.com/cameronian/ccrypto-ruby
gem 'ccrypto-ruby'

# or on Java runtime backed by JCE + bouncycastle
# https://github.com/cameronian/ccrypto-java
gem 'ccrypto-java'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install ccrypto
    $ gem install ccrypto-ruby # for Ruby runtime
    $ gem install ccrypto-java # for Java runtime


## Usage

Detail usage refers to spec files in ccrypto-ruby and ccrypto-java.

## Development hint

To add a different provider, runtime implementation requires to implement a provider class that has the following methods:

* All static method
  * provider\_name() - returns string indicating the provider
  * algo\_instance(\*args,&block) - return specific implementation class for the given arguments
  * asn1\_engine(\*args, &block) - return ASN1 engine from the runtime for given arguments
  * util\_instance(\*args, &block) - return utilities from the runtime. For example memory buffer, compression engine, data conversion etc. 


In the main entry for the runtime implementation, register this provider by calling:
```ruby
Ccrypto::Provider.instance.register(<provider class>)
```

That's it.

Refers to [Ccrypto ruby runtime](https://github.com/cameronian/ccrypto-ruby) or [Ccrypto Java runtime](https://github.com/cameronian/ccrypto-java) for more info.


