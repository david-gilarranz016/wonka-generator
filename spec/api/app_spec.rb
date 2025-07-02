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

  describe 'when receiving a GET request to /client' do
    it 'returns available client technologies' do
      # Read available technologies and build the expected response
      technologies = YAML.load_file('config/api/api.yaml')['clients'].map { |shell| shell['technology'] }
      expected_response = technologies.map { |tech| { 'technology' => tech } }

      # Perform the query
      get('/client')
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

  describe 'when receiving a POST request to /generator' do
    it 'adds Content-Type JSON header' do
      # Perform the action
      post('/generator', { 'test' => 'test'}.to_json, { 'CONTENT_TYPE' => 'application/json' })

      # Expect the header to be SET
      expect(last_response.headers['Content-Type']).to eq('application/json')
    end

    it 'returns 400 if requested invalid shell technology' do
      body = {
        shell: 'non-valid',
        client: 'python',
        features: []
      }.to_json

      # Perform the action
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' } )

      # Expect the status code to be 400
      expect(last_response.status).to be(400)
    end

    it 'returns 400 if requested invalid client technology' do
      body = {
        shell: 'php',
        client: 'non-valid',
        features: []
      }.to_json

      # Perform the action
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' } )

      # Expect the status code to be 400
      expect(last_response.status).to be(400)
    end

    it 'returns 400 if requested inexistent feature' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'non-existent'
          }
        ]
      }.to_json

      # Perform the action
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' } )

      # Expect the status code to be 400
      expect(last_response.status).to be(400)
    end

    it 'returns 400 if feature does not match its schema' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'ip-validator',
            arguments: [
              name: 'ip_whitelist',
              value: 'Not an IP, 10.10.10.10'
            ]
          }
        ]
      }.to_json

      # Perform the action
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' } )

      # Expect the status code to be 400
      expect(last_response.status).to be(400)
    end

    it 'returns 400 if output is invalid' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'file-upload'
          }
        ],
        output: {
          format: 'non-valid',
          'obfuscate-code': true
        }
      }.to_json

      # Perform the action
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Expect the status code to be 400
      expect(last_response.status).to be(400)
    end

    it 'generates PHP webshell matching its checksum' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'file-upload'
          }
        ],
        output: {
          format: 'png',
          'obfuscate-code': true
        }
      }.to_json

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Get the checksum of the generated file and compare it with the requested one
      response = JSON.parse(last_response.body)
      expected_checksum = OpenSSL::Digest::SHA256.file("public/#{response['shell']['url'].delete_prefix('/')}")
      expect(response['shell']['checksum']['value']).to eq(expected_checksum.to_s)

      # Expect the returned algorithm to be SHA256
      expect(response['shell']['checksum']['algorithm']).to eq('SHA256')
    end

    it 'generates PHP webshell with requested features' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'file-upload'
          },
          {
            key: 'execute-command-alternatives'
          }
        ],
        output: {
          format: 'gif',
          'obfuscate-code': false
        }
      }.to_json

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Expect the generated file to include the requested features
      response = JSON.parse(last_response.body)
      shell = File.read("public/#{response['shell']['url'].delete_prefix('/')}")

      expect(shell).to include('class UploadFileAction')
      expect(shell).to include('class IdentifyExecutionAlternatives')
    end

    it 'generates PHP webshell with randomly generated KEY' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'file-upload'
          }
        ],
        output: {
          format: 'gif',
          'obfuscate-code': false
        }
      }.to_json

      # Mock secure random to return mock key
      key = SecureRandom.hex(32)
      allow(SecureRandom).to receive(:hex).and_return(key)

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Expect the generated file to include the key
      response = JSON.parse(last_response.body)
      shell = File.read("public/#{response['shell']['url'].delete_prefix('/')}")

      expect(shell).to include(key)
      expect(SecureRandom).to have_received(:hex).with(32).at_least(:once)
    end

    it 'generates PHP webshell with randomly generated NONCE if requested' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'nonce-validation'
          }
        ],
        output: {
          format: 'gif',
          'obfuscate-code': false
        }
      }.to_json

      # Mock secure random to return mock nonce
      nonce = SecureRandom.hex(32)
      allow(SecureRandom).to receive(:hex).and_return(nonce)

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Expect the generated file to include the key
      response = JSON.parse(last_response.body)
      shell = File.read("public/#{response['shell']['url'].delete_prefix('/')}")

      expect(shell).to include(nonce)
      expect(SecureRandom).to have_received(:hex).with(32).at_least(:once)
    end

    it 'generates PHP webshell with correctly formatted IPs if requested validation' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'ip-validation',
            arguments: [
              name: 'IP_WHITELIST',
              value: '10.10.10.10, ::1'
            ]
          }
        ],
        output: {
          format: 'gif',
          'obfuscate-code': false
        }
      }.to_json

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Expect the generated file to include the IPs surrounded by quotes
      response = JSON.parse(last_response.body)
      shell = File.read("public/#{response['shell']['url'].delete_prefix('/')}")

      expect(shell).to include('"10.10.10.10","::1"')
    end

    it 'generates PHP webshell with single correctly formatted IP if requested' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'ip-validation',
            arguments: [
              name: 'IP_WHITELIST',
              value: '10.10.10.10'
            ]
          }
        ],
        output: {
          format: 'gif',
          'obfuscate-code': false
        }
      }.to_json

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Expect the generated file to include the IPs surrounded by quotes
      response = JSON.parse(last_response.body)
      shell = File.read("public/#{response['shell']['url'].delete_prefix('/')}")

      expect(shell).to match(/"10\.10\.10\.10"[^,]/)
    end

    it 'generates PHP obfuscated webshell' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'file-upload'
          },
          {
            key: 'execute-command-alternatives'
          }
        ],
        output: {
          format: 'php',
          'obfuscate-code': true
        }
      }.to_json

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Read the generated shell
      response = JSON.parse(last_response.body)
      shell = File.read("public/#{response['shell']['url'].delete_prefix('/')}")

      # Expect the shell to be obfuscated -> check there are no newlines and strings
      # are obfuscated
      expect(shell).not_to include("\n")
      expect(shell).to match(/".*\\x\d\d.*"/)
    end

    it 'ignores feature "execute-command-no-alternatives" if "execute-command-alternatives" is present' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'execute-command-no-alternatives'
          },
          {
            key: 'execute-command-alternatives'
          }
        ],
        output: {
          format: 'php',
          'obfuscate-code': false
        }
      }.to_json

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Read the generated shell
      response = JSON.parse(last_response.body)
      shell = File.read("public/#{response['shell']['url'].delete_prefix('/')}")

      # Expect the shell not no include a forcefull execution method set up
      expect(shell).not_to include('Required classes and definitions for Command-Execution with no alternatives identification')
    end

    it 'generates Python client matching its checksum' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'file-upload'
          }
        ],
        output: {
          format: 'png',
          'obfuscate-code': true
        }
      }.to_json

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Get the checksum of the generated file and compare it with the requested one
      response = JSON.parse(last_response.body)
      expected_checksum = OpenSSL::Digest::SHA256.file("public/#{response['client']['url'].delete_prefix('/')}")
      expect(response['client']['checksum']['value']).to eq(expected_checksum.to_s)

      # Expect the returned algorithm to be SHA256
      expect(response['client']['checksum']['algorithm']).to eq('SHA256')
    end

    it 'generates Python client with randomly generated KEY' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'file-upload'
          }
        ],
        output: {
          format: 'gif',
          'obfuscate-code': false
        }
      }.to_json

      # Mock secure random to return mock key
      key = SecureRandom.hex(32)
      allow(SecureRandom).to receive(:hex).and_return(key)

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Expect the generated file to include the key
      response = JSON.parse(last_response.body)
      client = File.read("public/#{response['client']['url'].delete_prefix('/')}")

      expect(client).to include(key)
      expect(SecureRandom).to have_received(:hex).with(32).at_least(:once)
    end

    it 'generates Python client with randomly generated NONCE' do
      body = {
        shell: 'php',
        client: 'python',
        features: [
          {
            key: 'nonce-validation'
          }
        ],
        output: {
          format: 'gif',
          'obfuscate-code': false
        }
      }.to_json

      # Mock secure random to return mock nonce
      nonce = SecureRandom.hex(16)
      allow(SecureRandom).to receive(:hex).and_return(nonce)

      # Send the request
      post('/generator', body, { 'CONTENT_TYPE' => 'application/json' })

      # Expect the generated file to include the key
      response = JSON.parse(last_response.body)
      client = File.read("public/#{response['client']['url'].delete_prefix('/')}")

      expect(client).to include(nonce)
      expect(SecureRandom).to have_received(:hex).with(16).at_least(:once)
    end
  end

  describe 'adds CORS headers' do
    it 'to any request' do
      get('/web-shell')

      expect(last_response.headers['Access-Control-Allow-Origin']).to eq('*')
    end

    it 'to OPTIONS requests to the /web-shell endpoint' do
      options('/web-shell')

      expect(last_response.headers['Allow']).to eq('GET')
      expect(last_response.headers['Access-Control-Allow-Origin']).to eq('*')
    end

    it 'to OPTIONS requests to the /client endpoint' do
      options('/client')


      expect(last_response.headers['Allow']).to eq('GET')
      expect(last_response.headers['Access-Control-Allow-Origin']).to eq('*')
    end

    it 'to OPTIONS requests to the /generator endpoint' do
      options('/generator')


      expect(last_response.headers['Allow']).to eq('POST')
      expect(last_response.headers['Access-Control-Allow-Origin']).to eq('*')
      expect(last_response.headers['Access-Control-Allow-Headers']).to eq('Content-Type, Accept')
    end
  end
end
