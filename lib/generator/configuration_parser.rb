module ConfigurationParser
  def self.parse(configuration_file)
    # Load the YAML string
    yaml = YAML.load(configuration_file) 

    # Parse the yaml document
    fragments = {}
    yaml['fragments'].each do |fragment|
      key = fragment['key']
      sources = fragment['sources']
      arguments = fragment.key? 'arguments' ? fragment['arguments'] : []
      fragments[key] = Fragment.new(key, sources, arguments)
    end

    # Create and return a configuration object
    Configuration.new(fragments)
  end
end
