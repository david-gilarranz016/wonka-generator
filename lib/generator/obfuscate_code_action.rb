class ObfuscateCodeAction
  def initialize(obfuscator)
    @obfuscator = obfuscator
  end

  def transform(product)
    product.code = @obfuscator.obfuscate(product.code)
  end
end
