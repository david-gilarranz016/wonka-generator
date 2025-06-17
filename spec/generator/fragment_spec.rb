describe Fragment do
  it 'has a key that identifies it' do
    # Create a new fragment
    key = 'test-key'
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

  it 'stores a list of arguments required to correctly use the fragment' do
    # Create a new fragment
    arguments = ['KEY']
    fragment = Fragment.new('setup-encryption', [], arguments)

    # Expect the key to be stored and readable
    expect(fragment.arguments).to eq(arguments)
  end
end
