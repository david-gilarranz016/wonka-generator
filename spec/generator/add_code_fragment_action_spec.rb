################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe AddCodeFragmentAction do
  it 'uses the supplied code factory to add fragment to the Product' do
    # Create a mock CodeFactory
    fragment = 'This is a fragment'
    feature = 'test'
    run_adds_simple_fragment_scenario(feature, fragment)
  end
  
  it 'uses the supplied code factory to add different fragment to the Product' do
    # Create a mock CodeFactory
    fragment = 'This is a fragment'
    feature = 'test'
    run_adds_simple_fragment_scenario(feature, fragment)
  end

  it 'adds a fragment instead of deleting code' do
    product = Product.new
    product.code = 'Initial code'
    run_does_not_delete_previous_code_scenario(product)
  end

  it 'adds a different fragment instead of deleting code' do
    product = Product.new
    product.code = 'Different initial code'
    run_does_not_delete_previous_code_scenario(product)
  end

  it 'adds a fragment with arguments' do
    feature = 'ip-whitelist'
    arguments = { 'WHITELIST' => '"127.0.0.1", "::1"' }
    run_fragment_with_arguments_scenario(feature, arguments)
  end

  it 'adds a different fragment with arguments' do
    feature = 'setup-encryption'
    arguments = { 'KEY' => 'sample_key' }
    run_fragment_with_arguments_scenario(feature, arguments)
  end
end

################################################################################
#                                                                              #
# Test scenarios to reduce test code duplication                               #
#                                                                              #
################################################################################

def run_adds_simple_fragment_scenario(feature, fragment)
  # Create a mock CodeFactory
  code_factory = instance_double(CodeFactory)
  expect(code_factory).to receive(:build_fragment).with(feature, nil).and_return(fragment)

  # Create and run the action
  product = Product.new
  action = AddCodeFragmentAction.new(code_factory, feature)
  action.transform(product)

  # Expect the product to contain the fragment
  expect(product.code).to include(fragment)
end

def run_does_not_delete_previous_code_scenario(product)
  # Save the previous content of the product
  code = product.code

  # Create a mock CodeFactory
  code_factory = instance_double(CodeFactory)
  expect(code_factory).to receive(:build_fragment).and_return('This is a fragment')

  # Create and run the action
  action = AddCodeFragmentAction.new(code_factory, 'test')
  action.transform(product)

  # Expect the product to contain the fragment
  expect(product.code).to include(code)
end

def run_fragment_with_arguments_scenario(feature, arguments)
  # Create a mock CodeFactory and expect it to receive the arguments for the fragment
  code_factory = instance_double(CodeFactory)
  expect(code_factory).to receive(:build_fragment).with(feature, arguments).and_return('')

  # Create and run the action
  product = Product.new
  action = AddCodeFragmentAction.new(code_factory, feature, arguments)
  action.transform(product)
end
