# coding: utf-8
# frozen_string_literal: true
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cloud_payments/version'

Gem::Specification.new do |spec|
  spec.name          = 'cloud_payments'
  spec.version       = CloudPayments::VERSION
  spec.authors       = ['undr', 'kirillplatonov']
  spec.email         = ['undr@yandex.ru', 'mail@kirillplatonov.com']
  spec.summary       = %q{CloudPayments ruby client}
  spec.description   = %q{CloudPayments ruby client}
  spec.homepage      = 'https://github.com/platmart/cloud_payments'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}){|f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_dependency 'faraday', '~> 2.0'
  spec.add_dependency 'multi_json', '~> 1.11'
  spec.add_dependency 'hashie', '~> 3.4'

  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.9'
end
