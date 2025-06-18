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
end
