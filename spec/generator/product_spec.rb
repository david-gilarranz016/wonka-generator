describe Product do
  it 'contains code' do
    # Create a product
    product = Product.new

    # Add code to it
    code = '<?php echo "test"; ?>'
    product.code = code

    # Expect the code to be stored
    expect(product.code).to eq(code)
  end

  it 'contains different code' do
    # Create a product
    product = Product.new

    # Add code to it
    code = '<?php echo "different_test"; ?>'
    product.code = code

    # Expect the code to be stored
    expect(product.code).to eq(code)
  end

  it 'contains the path of the output file' do
    # Create a product
    product = Product.new

    # Add a file to it
    file = 'output/ea75b9ddc187f84549deda4a52fe82dc8a98bab6b636d9bc8b5193dd2f009a91.php'
    product.file = file

    # Expect the file to be stored
    expect(product.file).to eq(file)
  end

  it 'contains the path of a different output file' do
    # Create a product
    product = Product.new

    # Add a file to it
    file = 'output/a6748d1f5e9aa10b9511a0446ae051c3fc3ba9b44b36a98eb5ce2d633af0ccc7.php'
    product.file = file

    # Expect the file to be stored
    expect(product.file).to eq(file)
  end
end
