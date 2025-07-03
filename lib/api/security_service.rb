class SecurityService
  include Singleton

  def valid?(body)
    # Validate the request body
    valid = technology_valid?(body)
    valid &&= features_valid?(body)
    valid &&= output_valid?(body)

    # Return the validation result
    valid
  end

  private

  def technology_valid?(body)
    config = YAML.load_file('config/api/api.yaml')

    # Return true if both the client and shell technology are in the configuration file
    config['shells'].map { |shell| shell['technology'] }.include?(body['shell']) &&
      config['clients'].map { |client| client['technology'] }.include?(body['client'])
  end

  def features_valid?(body)
    schemas = YAML.load_file('config/api/schemas.yaml')['features']

    # If no features are requested, the request is invalid
    valid = body.key?('features')

    if valid
      body['features'].each do |feature|
        # Check if the feature exists and validate it against it's JSON schema
        schema = schemas.select { |schema| schema['key'] == feature['key'] }.first
        valid &&= (!schema.nil? && JSON::Validator.validate(schema['schema'], feature))
      end
    end

    valid
  end

  def output_valid?(body)
    # Load the schema for the output object
    schema = YAML.load_file('config/api/schemas.yaml')['output']

    # Check if the body includes an output section, and if it matches the schema
    body.key?('output') && JSON::Validator.validate(schema, body['output'])
  end
end
