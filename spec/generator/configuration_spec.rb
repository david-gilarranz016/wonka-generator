describe Configuration do
  it 'contains a series of fragments' do
    # Initialize the configuration object
    fragments = {
      'base' => Fragment.new('base', ['php/base.php'], ['KEY']),
      'identify-alternatives' => Fragment.new('identify-alternatives', ['php/identify_alternatives.php'], [])
    }
    configuration = Configuration.new(fragments) 

    # Expect the fragments to be accessible
    expect(configuration.fragments).to eq(fragments)
  end
end
