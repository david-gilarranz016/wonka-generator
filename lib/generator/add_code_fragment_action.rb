class AddCodeFragmentAction
  def initialize(code_factory, fragment, arguments = nil)
    @code_factory = code_factory
    @fragment = fragment
    @arguments = arguments
  end

  def transform(product)
    # Add the code fragment to the product
    product.code << @code_factory.build_fragment(@fragment, @arguments)
  end
end
