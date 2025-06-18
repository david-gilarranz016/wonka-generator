class Generator
  def initialize(stages)
    @stages = stages
  end

  def generate
    # Generate an empty product and apply all transformations
    product = Product.new
    @stages.each { |stage| stage.transform(product) }

    # Return the resulting product
    product
  end
end
