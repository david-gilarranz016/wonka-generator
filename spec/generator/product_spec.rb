################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe Product do
  it 'contains code' do
    code = '<?php echo "test"; ?>'
    run_stores_code_scenario(code)
  end

  it 'contains different code' do
    code = '<?php echo "different_test"; ?>'
    run_stores_code_scenario(code)
  end

  it 'contains the path of the output file' do
    file = 'output/ea75b9ddc187f84549deda4a52fe82dc8a98bab6b636d9bc8b5193dd2f009a91.php'
    run_stores_file_scenario(file)
  end

  it 'contains the path of a different output file' do
    file = 'output/a6748d1f5e9aa10b9511a0446ae051c3fc3ba9b44b36a98eb5ce2d633af0ccc7.php'
    run_stores_file_scenario(file)
  end

  it 'contains the file checksum' do
    checksum = 'a994a33f4e986013d7b54854cf062f28da28a280c832ba499e717d64034d445f'
    run_stores_checksum_scenario(checksum)
  end

  it 'contains a different file checksum' do
    checksum = '2c08b9f1a3f20efabea4c43603536d8c8d559df00727ddc1fba39ec9d6e47cf9'
    run_stores_checksum_scenario(checksum)
  end
end

################################################################################
#                                                                              #
# Test scenarios to reduce test code duplication                               #
#                                                                              #
################################################################################

def run_stores_code_scenario(code)
  # Create a product
  product = Product.new

  # Add code to it
  product.code = code

  # Expect the code to be stored
  expect(product.code).to eq(code)
end

def run_stores_file_scenario(file)
  # Create a product
  product = Product.new

  # Add code to it
  product.file = file

  # Expect the code to be stored
  expect(product.file).to eq(file)
end

def run_stores_checksum_scenario(checksum)
  # Create a product
  product = Product.new

  # Add checksum to it
  product.checksum = checksum

  # Expect the checksum to be stored
  expect(product.checksum).to eq(checksum)
end
