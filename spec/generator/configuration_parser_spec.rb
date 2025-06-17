################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe ConfigurationParser do
  it 'reads a YAML document containing the expected configuration' do
    # Create a sample yaml document
    yaml = <<~YAML
    ---
    fragments:
      - key: base
        sources:
          - php/base.php
          - php/base-auxiliary.php
      - key: feature
        sources:
          - php/feature.php
        arguments:
          - ARGUMENT
    YAML

    # Create a configuration object mimicking the YAML document
    expected_configuration = Configuration.new(Hash[
      'base' => Fragment.new('base', ['php/base.php', 'php/base-auxiliary.php'], []),
      'feature' => Fragment.new('feature', ['php/feature.php'], ['ARGUMENT'])
    ])

    # Parse the configuration document and compare it to the expected
    configuration = ConfigurationParser.parse(yaml)
    same = same_configuration?(configuration, expected_configuration)
    expect(same).to be_truthy
  end

  it 'reads a different YAML document containing the expected configuration' do
    # Create a sample yaml document
    yaml = <<~YAML
    ---
    fragments:
      - key: base
        sources:
          - php/base.php
        arguments:
          - KEY
      - key: feature
        sources:
          - php/feature_part_1.php
          - php/feature_part_2.php
    YAML

    # Create a configuration object mimicking the YAML document
    expected_configuration = Configuration.new(Hash[
      'base' => Fragment.new('base', ['php/base.php'], ['KEY']),
      'feature' => Fragment.new('feature', ['php/feature_part_1.php', 'php/feature_part_1.php'], [])
    ])

    # Parse the configuration document and compare it to the expected
    configuration = ConfigurationParser.parse(yaml)
    same = same_configuration?(configuration, expected_configuration)
    expect(same).to be_truthy
  end
end

################################################################################
#                                                                              #
# Helper functions                                                             #
#                                                                              #
################################################################################

def same_configuration?(conf1, conf2)
  # Initialze the return value to True
  same = true
  
  # Expect both objectes to contain the same keys
  same &&= conf1.fragments.keys == conf2.fragments.keys

  # Expect all fragments to match
  conf1.fragments.keys do |key|
    same &&= conf1.fragments[key].key == conf2.fragments[key].key
    same &&= conf1.fragments[key].sources == conf2.fragments[key].sources
    same &&= conf1.fragments[key].arguments == conf2.fragments[key].arguments
  end

  # Return the result of the comparison 
  same
end
