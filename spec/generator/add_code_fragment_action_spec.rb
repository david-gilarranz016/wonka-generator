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
end

################################################################################
#                                                                              #
# Test scenarios to reduce test code duplication                               #
#                                                                              #
################################################################################

def run_adds_simple_fragment_scenario(feature, fragment)
  # Create a mock CodeFactory
  code_factory = instance_double(CodeFactory)
  expect(code_factory).to receive(:build_fragment).with(feature).and_return(fragment)

  # Create and run the action
  product = Product.new
  action = AddCodeFragmentAction.new(code_factory, feature)
  action.transform(product)

  # Expect the product to contain the fragment
  expect(product.code).to eq(fragment)
end
