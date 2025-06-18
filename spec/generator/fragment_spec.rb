################################################################################
#                                                                              # 
# Test cases                                                                   # 
#                                                                              # 
################################################################################

describe Fragment do
  it 'has a key that identifies it' do
    # Create a new fragment
    key = 'test-key'
    fragment = Fragment.new(key, [], [])

    # Expect the key to be stored and readable
    expect(fragment.key).to eq(key)
  end

  it 'has a different key that identifies it' do
    # Create a new fragment
    key = 'different-test-key'
    fragment = Fragment.new(key, [], [])

    # Expect the key to be stored and readable
    expect(fragment.key).to eq(key)
  end

  it 'stores the source files that must be included' do
    # Create a new fragment
    sources = ['php/action.php', 'php/execute_command_action.php']
    fragment = Fragment.new('execute-command', sources, [])

    # Expect the key to be stored and readable
    expect(fragment.sources).to eq(sources)
  end

  it 'stores different source files that must be included' do
    # Create a new fragment
    sources = ['php/base.php']
    fragment = Fragment.new('base', sources, [])

    # Expect the key to be stored and readable
    expect(fragment.sources).to eq(sources)
  end

  it 'stores a list of arguments required to correctly use the fragment' do
    # Create a new fragment
    arguments = ['KEY']
    fragment = Fragment.new('setup-encryption', [], arguments)

    # Expect the key to be stored and readable
    expect(fragment.arguments).to eq(arguments)
  end

  it 'stores an empty list if there are no arguments required' do
    # Create a new fragment
    arguments = []
    fragment = Fragment.new('setup-encryption', [], arguments)

    # Expect the key to be stored and readable
    expect(fragment.arguments).to eq(arguments)
  end
end
