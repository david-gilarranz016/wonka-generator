class AddCodeFragmentAction
  def initialize(code_factory, fragment)
    @code_factory = code_factory
    @fragment = fragment
  end

  def transform(product)
    # Add the code fragment to the product
    product.code = @code_factory.build_fragment(@fragment)
  end
end
