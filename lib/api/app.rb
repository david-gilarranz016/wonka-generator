class App < Sinatra::Base
  before do
    # Set the Content Type for all responses
    content_type :json
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
    technologies = YAML.load_file('config/api/api.yaml')['clients'].map do |client|
      {
        'technology' => client['technology']
      }
    end

    # Convert the technologies array to JSON and send the response
    technologies.to_json
  end

  post '/generator' do
    # Validate the request
    body = JSON.parse(request.body.read)
    halt 400 unless validate(body)
  end

  private

  def validate(body)
    valid = true
    config = YAML.load_file('config/api/api.yaml')

    # Validate requested technologies
    valid &&= config['shells'].map { |shell| shell['technology'] }.include? body['shell']
    valid &&= config['clients'].map { |client| client['technology'] }.include? body['client']

    valid
  end
end
