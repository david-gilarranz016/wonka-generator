# frozen_string_literal: true

require_relative 'lib/generator'

# Use standard protection to prevent common attacks
require 'rack/protection'
require 'sinatra/cross_origin'

use Rack::Protection, :except => :http_origin

map '/api' do
  run App
end
