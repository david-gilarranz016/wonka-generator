# frozen_string_literal: true

require_relative 'lib/generator'

# Use standard protection to prevent common attacks
require 'rack/protection'
require 'rack/attack'
require 'sinatra/cross_origin'
require 'logger'
require 'redis'

# Set up security protections
use Rack::Protection, { except: %i[http_origin remote_token] }
use Rack::Attack

Rack::Attack.cache.store = Redis.new(url: "redis://#{ENV['REDIS_HOST']}:#{ENV['REDIS_PORT']}")
Rack::Attack.throttle('Block requests based on IP', limit: 2, period: 1) do |request|
  request.ip
end

map '/api' do
  run App
end
