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

    run_single_souce_file_test_scenario(key, source, content)
  end

  it 'returns the code contained in a different file' do
    key = 'footer'
    source = 'footer.php'
    content = '<?php echo "footer" ?>'

    run_single_souce_file_test_scenario(key, source, content)
  end

  it 'returns the code contained in multiple files' do
    key = 'base'
    sources = {
      'base.php' => '<?php echo "base" ?>',
      'footer.php' => '<?php echo "footer" ?>'
    }

    run_multiple_souce_file_test_scenario(key, sources)
  end

  it 'returns the code contained in different multiple files' do
    key = 'execute-command'
    sources = {
      'action.php' => '<?php echo "action" ?>',
      'execute_comand_action.php' => '<?php system("id") ?>'
    }

    run_multiple_souce_file_test_scenario(key, sources)
  end
end

################################################################################
#                                                                              #
# Test scenarios to reduce test-code duplication                               #
#                                                                              #
################################################################################

def run_single_souce_file_test_scenario(key, source, contents)
    # Create a CodeGenerator
    yaml = <<~CONFIG
    ---
    fragments:
      - key: #{key}
        sources:
          - #{source}
    CONFIG
    configuration = ConfigurationParser.parse(yaml)
    code_factory = CodeFactory.new(configuration)

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

def run_multiple_souce_file_test_scenario(key, sources)
  # Create a config file
  yaml = <<~CONFIG
  ---
  fragments:
    - key: #{key}
      sources:
  CONFIG
  sources.keys.each { |key| yaml << "      - #{key}\n" }

  # Initialize the CodeFactory
  configuration = ConfigurationParser.parse(yaml) 
  code_factory = CodeFactory.new(configuration)

  # Create a fresh virtual file system
  FakeFS.with_fresh do
    # Create a file for each source
    contents = ''
    sources.keys.each do |source|
      # Write the file contents
      File.open(source, 'w') { |f| f.write(sources[source]) }

      # Append the content to the content list
      contents << sources[source]
    end

    # Use the CodeFactory to create a fragment
    fragment = code_factory.build_fragment(key)

    # Compare the fragment with the expected contents
    expect(fragment).to eq(contents)
  end
end
