# frozen_string_literal: true

require 'yaml'
require 'securerandom'
require 'openssl'
require 'sinatra/base'
require 'json-schema'

require_relative 'generator/fragment'
require_relative 'generator/configuration'
require_relative 'generator/configuration_parser'
require_relative 'generator/code_factory'
require_relative 'generator/product'
require_relative 'generator/add_code_fragment_action'
require_relative 'generator/stage'
require_relative 'generator/generator'
require_relative 'generator/file_info'
require_relative 'generator/generate_output_file_action'
require_relative 'generator/output'
require_relative 'generator/php_obfuscator'
require_relative 'generator/obfuscate_code_action'

require_relative 'api/app'
require_relative 'api/security_service'
