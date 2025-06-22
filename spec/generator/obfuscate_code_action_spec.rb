################################################################################
#                                                                              #
# Test Cases                                                                   #
#                                                                              #
################################################################################

describe ObfuscateCodeAction do
  it 'obfuscate the source code' do
    obfuscated_code = 'Sample obfuscation process output'
    run_obfuscates_code_scenario(obfuscated_code)
  end

  it 'obfuscate the source code using a different obfuscator' do
    obfuscated_code = 'Different obfuscation process output'
    run_obfuscates_code_scenario(obfuscated_code)
  end
end

################################################################################
#                                                                              #
# Test scenarios to reduce test-case code duplication                          #
#                                                                              #
################################################################################

def run_obfuscates_code_scenario(obfuscated_code)
  # Create an obfuscator
  obfuscator = TestObfuscator.new(obfuscated_code)

  # Run the action
  product = Product.new
  action = ObfuscateCodeAction.new(obfuscator)
  action.transform(product)

  # Expect the code to have been obfuscated
  expect(product.code).to eq(obfuscated_code)
end

################################################################################
#                                                                              #
# Helper functions and classes                                                 #
#                                                                              #
################################################################################

class TestObfuscator
  def initialize(code)
    @code = code
  end

  def obfuscate(code)
    @code
  end
end
