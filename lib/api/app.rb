class App < Sinatra::Base
  before do
    # Set the Content Type for all responses
    content_type :json
  end

  get '/web-shell' do
    # Read available technologies and return them
    response = YAML.load_file('config/api/api.yaml')['shells'].map do |shell|
      {
        'technology' => shell['technology'],
        'url' => "/web-shell/#{shell['technology']}"
      }
    end

    # JSON encode and send the response
    response.to_json
  end
end
