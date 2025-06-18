describe Stage do
  it 'uses supplied actions to transform a product' do
    # Create a series of actions and expect them to receive the product
    product = Product.new
    actions = [ instance_double(AddCodeFragmentAction) ] * 3
    actions.each do |action|
      expect(action).to receive(:transform).with(product)
    end

    # Create a new stage and run it
    stage = Stage.new(actions)
    stage.transform(product)
  end
end
