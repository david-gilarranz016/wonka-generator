class CodeFactory
  def initialize(configuration)
    @configuration = configuration
  end

  def build_fragment(key)
    fragment = ''

    # Read the source file and return the contents
    source = @configuration.fragments[key].sources.first
    File.open(source, 'r') { |f| fragment << f.read }

    fragment
  end
end
