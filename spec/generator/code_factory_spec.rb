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
    key = 'base'
    source = 'base.php'
    content = '<?php echo "base" ?>'

    run_single_souce_file_test_scenario(key, source, content)
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
    code_generator = CodeFactory.new(configuration)

    # Create a fresh virtual file system
    FakeFS.with_fresh do
      # Create a test file
      File.open(source, 'w') { |f| f.write(contents) }

      # Use the CodeGenerator to create a fragment
      fragment = code_generator.build_fragment(key)

      # Compare the fragment with the file contents
      expect(fragment).to eq(contents)
    end
end
