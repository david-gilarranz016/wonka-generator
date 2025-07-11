class App < Sinatra::Base

  set :static, true
  set :public_folder, 'public'
  set :logging, true

  configure do
    # Allow Cross-Origin requests
    enable :cross_origin
  end

  before do
    # Set the Content Type for all responses
    content_type :json

    # Allow Cross Origin requests
    response.headers['Access-Control-Allow-Origin'] = '*'
  end

  get '/web-shell' do
    # Read available technologies and return them
    technologies = YAML.load_file('config/api/api.yaml')['shells'].map do |shell|
      {
        'technology' => shell['technology'],
        'url' => "/web-shell/#{shell['technology']}"
      }
    end

    # Convert the technologies array to JSON and send the response
    technologies.to_json
  end

  get '/web-shell/:technology' do |technology|
    # Read the features for the requested technology
    shell = YAML.load_file('config/api/api.yaml')['shells']
                .select { |shell| shell['technology'] == technology }
                .first

    # Check if the reuqested technology exists
    if shell.nil?
      status 404
      response = nil
    else
      # Convert the response to JSON and send it
      response = shell['features'].to_json
    end

    # Return the response
    response
  end

  get '/client' do
    # Read available technologies and return them
    technologies = YAML.load_file('config/api/api.yaml')['clients']

    # Convert the technologies array to JSON and send the response
    technologies.to_json
  end

  post '/generator' do
    # Validate the request
    body = JSON.parse(request.body.read)
    halt 400 unless SecurityService.instance.valid?(body)

    # Generate the shell and client
    key = SecureRandom.hex(32)
    nonce = SecureRandom.hex(16)
    shell_info = GeneratorBuilder.instance.build_shell_generator(body, key, nonce).generate
    client_info = GeneratorBuilder.instance.build_client_generator(body, key, nonce).generate

    # Log the request
    log_entry = "#{request.ip} - "
    log_entry << "features[#{body['features'].map { |feature| feature['key'] }.join(',')}],"
    log_entry << "shell[url=/#{shell_info.file},checksum=#{shell_info.checksum}],"
    log_entry << "client[url=/#{client_info.file},checksum=#{client_info.checksum}]"
    logger.info log_entry

    # Create the response
    {
      shell: {
        url: '/' + shell_info.file,
        checksum: {
          algorithm: 'SHA256',
          value: shell_info.checksum
        }
      },
      client: {
        url: '/' + client_info.file,
        checksum: {
          algorithm: 'SHA256',
          value: client_info.checksum
        }
      }
    }.to_json
  end

  # Options requests -> to correctly handle CORS preflight requests
  options '/web-shell' do
    response.headers['Allow'] = 'GET'
  end

  options '/client' do
    response.headers['Allow'] = 'GET'
  end

  options '/generator' do
    response.headers['Allow'] = 'POST'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept'
  end
end
