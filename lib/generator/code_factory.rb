class CodeFactory
  def initialize(configuration)
    @configuration = configuration
  end

  def build_fragment(key)
    fragment = ''

    # Read the source files and append the contents to the fragment
    @configuration.fragments[key].sources.each do |source|
      File.open(source, 'r') { |f| fragment << f.read }
    end

    fragment
  end
end
