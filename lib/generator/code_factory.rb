class CodeFactory
  def initialize(configuration)
    @configuration = configuration
  end

  def build_fragment(key, arguments = nil)
    fragment = ''

    # Read the source files and append the contents to the fragment
    @configuration.fragments[key].sources.each do |source|
      File.open(source, 'r') { |f| fragment << f.read }
    end

    # Apply arguments
    unless arguments.nil?
      arguments.each_key do |argument|
        fragment.gsub!(argument, arguments[argument])
      end
    end

    # Return generated fragment
    fragment
  end
end
