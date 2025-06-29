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
    halt 400 unless SecurityService.instance.valid?(body)

    # Generate the shell and client
    key = SecureRandom.hex(64)
    nonce = SecureRandom.hex(32)
    shell_info = generate_web_shell(body, key, nonce)
    client_info = generate_client(body, key, nonce)

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

  private

  def generate_web_shell(body, key, nonce)
    # Create a code factory for the requested shell technology
    config_file = File.read("config/generator/shells/#{body['shell']}.yaml")
    configuration = ConfigurationParser.parse(config_file)
    code_factory = CodeFactory.new(configuration)

    # Create the stage array and add the initial Base stage
    stages = []
    stages << Stage.new([AddCodeFragmentAction.new(code_factory, 'base', { 'KEY' => key })])

    # Add the "feature" stage, where all requested features are added
    actions = []
    body['features'].each do |feature|
      # Get the requested feature's key
      key = feature['key']

      # If there are arguments, build the argument's hash. Special case -> nonce
      arguments = {}
      if key == 'nonce-validation'
        arguments['NONCE'] = nonce
      elsif !feature['arguments'].nil?
        feature['arguments'].each { |argument| arguments[argument['name']] = argument['value'] }
      else
        arguments = nil
      end

      # Add the feature to the stage
      actions << AddCodeFragmentAction.new(code_factory, key, arguments)
    end
    stages << Stage.new(actions)

    # Add the Footer stage to complete the shell generation
    stages << Stage.new([AddCodeFragmentAction.new(code_factory, 'footer')])

    # Add the output generation stage
    actions = []
    obfuscator = Object.const_get("#{body['shell'].capitalize}Obfuscator").new
    actions << ObfuscateCodeAction.new(PhpObfuscator.new) if body['output']['obfuscate-code']

    format = Output.constants.detect { |format| format == body['output']['format'].upcase.to_sym }
    format = Output.const_get(format)
    actions << GenerateOutputFileAction.new(format)
    stages << Stage.new(actions)

    # Generate the requested shell
    generator = Generator.new(stages)
    generator.generate
  end

  def generate_client(body, key, nonce)
    # Create a code factory for the requested client technology
    config_file = File.read("config/generator/shells/#{body['shell']}.yaml")
    configuration = ConfigurationParser.parse(config_file)
    code_factory = CodeFactory.new(configuration)

    # Create the stage array and add the base stage
    stages = []
    stages << Stage.new([AddCodeFragmentAction.new(code_factory, 'base', { 'KEY' => key, 'NONCE' => nonce })])

    # Add the output generation stage
    format = Output.constants.detect { |format| format == body['client'].upcase.to_sym }
    format = Output.const_get(format)
    stages << Stage.new([GenerateOutputFileAction.new(format)])

    # Generate the client and return the result
    generator = Generator.new(stages)
    generator.generate
  end
end
