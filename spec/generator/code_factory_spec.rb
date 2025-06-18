################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe CodeFactory do
  # Use a virtual file-system for the IO tests
  include FakeFS::SpecHelpers
  
  it 'returns the code contained in a source file' do
    key = 'base'
    source = 'base.php'
    content = '<?php echo "base" ?>'

    run_single_source_file_test_scenario(key, source, content)
  end

  it 'returns the code contained in a different file' do
    key = 'footer'
    source = 'footer.php'
    content = '<?php echo "footer" ?>'

    run_single_source_file_test_scenario(key, source, content)
  end

  it 'returns the code contained in multiple files' do
    key = 'base'
    sources = {
      'base.php' => '<?php echo "base" ?>',
      'footer.php' => '<?php echo "footer" ?>'
    }

    run_multiple_source_file_test_scenario(key, sources)
  end

  it 'returns the code contained in different multiple files' do
    key = 'execute-command'
    sources = {
      'action.php' => '<?php echo "action" ?>',
      'execute_comand_action.php' => '<?php system("id") ?>'
    }

    run_multiple_source_file_test_scenario(key, sources)
  end

  it 'returns the code fragment with the argument replaced by its value' do
    key = 'base'
    sources = { 'base.php' => '<?php echo "KEY" ?>' }
    arguments = { 'KEY' => 'this_is_a_sample_key' }

    run_arguments_test_scenario(key, sources, arguments)
  end

  it 'returns the code fragment with several arguments replaced by their values' do
    key = 'whitelist'
    sources = {
      'whitelist.php' => '<?php echo "[WHITELIST]" ?>',
      'footer.php' => '<?php echo "STRING" ?>'
    }
    arguments = { 'WHITELIST' => 'valid_1, valid_2', 'STRING' => 'sample_string' }

    run_arguments_test_scenario(key, sources, arguments)
  end
end

################################################################################
#                                                                              #
# Test scenarios to reduce test-code duplication                               #
#                                                                              #
################################################################################

def run_single_source_file_test_scenario(key, source, contents)
    # Create a code factory
    code_factory = build_code_factory(key, [source])

    # Create a fresh virtual file system
    FakeFS.with_fresh do
      # Create a test file
      File.open(source, 'w') { |f| f.write(contents) }

      # Use the CodeFactory to create a fragment
      fragment = code_factory.build_fragment(key)

      # Compare the fragment with the file contents
      expect(fragment).to eq(contents)
    end
end

def run_multiple_source_file_test_scenario(key, sources)
  # Create a code factory
  code_factory = build_code_factory(key, sources.keys)

  # Create a fresh virtual file system
  FakeFS.with_fresh do
    # Create a file for each source
    contents = create_source_files(sources)

    # Use the CodeFactory to create a fragment
    fragment = code_factory.build_fragment(key)

    # Compare the fragment with the expected contents
    expect(fragment).to eq(contents)
  end
end

def run_arguments_test_scenario(key, sources, arguments)
  # Get the code factory
  code_factory = build_code_factory(key, sources.keys, arguments.keys)

  # Create a fresh virtual file system
  FakeFS.with_fresh do
    # Create a file for each source
    contents = create_source_files(sources)

    # Substitute the arguments with their values
    arguments.each_key do |argument|
      contents.gsub!(argument, arguments[argument])
    end

    # Use the CodeFactory to create a fragment
    fragment = code_factory.build_fragment(key, arguments)

    # Compare the fragment with the expected contents
    expect(fragment).to eq(contents)
  end
end

################################################################################
#                                                                              #
# Helper functions                                                             #
#                                                                              #
################################################################################

def build_code_factory(key, sources, arguments = nil)
  # Create the YAML template
  yaml = <<~CONFIG
  ---
  fragments:
    - key: #{key}
      sources:
  CONFIG

  # Add each source to the YAML document
  sources.each { |source| yaml << "      - #{source}\n" }

  # If there are arguments, add them too
  unless arguments.nil? 
    yaml << "    arguments:\n"
    arguments.each { |argument| yaml << "      - #{argument}\n" }
  end

  # Create and return the CodeFactory
  configuration = ConfigurationParser.parse(yaml) 
  CodeFactory.new(configuration)
end

def create_source_files(sources)
  contents = ''
  
  # Create each source file
  sources.each_key do |source|
    # Write the file contents
    File.open(source, 'w') { |f| f.write(sources[source]) }

    # Append the content to the content list
    contents << sources[source]
  end

  # Return full fragment code
  contents
end
