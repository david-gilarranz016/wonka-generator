# frozen_string_literal: true

require 'rack/test'

describe App do
  include Rack::Test::Methods

  def app
    App.new
  end

  describe 'when receiving a GET request to /web-shell' do
    it 'returns available web-shell technologies' do
      # Read available technologies and build the expected response
      technologies = YAML.load_file('config/api/api.yaml')['shells'].map { |shell| shell['technology'] }
      expected_response = technologies.map { |tech| { 'technology' => tech, 'url' => "/web-shell/#{tech}" } }

      # Perform the query
      get('/web-shell')
      response = JSON.parse(last_response.body)

      # Compare the response with the expected one
      expect(response).to eq(expected_response)
    end

    it 'adds Content-Type JSON header' do
      # Perform the query
      get('/web-shell')

      # Expect the header to be SET
      expect(last_response.headers['Content-Type']).to eq('application/json')
    end
  end

  describe 'when receiving a GET request to /web-shell/:technology' do
    it 'returns available features for the requested technology' do
      # Read all features for the PHP technology
      shell = YAML.load_file('config/api/api.yaml')['shells']
                  .select { |shell| shell['technology'] == 'php' }
                  .first
      expected_response = shell['features']

      # Perform the query
      get('/web-shell/php')
      response = JSON.parse(last_response.body)

      # Compare the response with the expected one
      expect(response).to eq(expected_response)
    end

    it 'returns 404 if the technology is not available' do
      # Perform the query
      get('/web-shell/non-existent')

      # Expect the status code to be 404
      expect(last_response.status).to be(404)
    end

    it 'adds Content-Type JSON header' do
      # Perform the query
      get('/web-shell')

      # Expect the header to be SET
      expect(last_response.headers['Content-Type']).to eq('application/json')
    end
  end
end
