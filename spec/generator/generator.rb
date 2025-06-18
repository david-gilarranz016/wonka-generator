################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe Generator do
  it 'uses a series of Stages to transform a product' do
    # Create a generator with a series of sample stages
    stages = [
      Stage[ TestAction.new('a'), TestAction.new('b'), TestAction.new('c') ],
      Stage[ TestAction.new('d'), TestAction.new('e')
    ]
    generator = Generator.new(stages)

    # Expect the generated product to contain the string 'abcde' as code
    product = generator.generate
    expect(product.code).to eq('abcde')
  end

  it 'uses a different series of Stages to transform a product' do
    # Create a generator with a series of sample stages
    stages = [
      Stage[ TestAction.new('1'), TestAction.new('2') ],
      Stage[ TestAction.new('3'), TestAction.new('4'), TestAction.new('5') ]
      Stage[ TestAction.new('6') ]
    ]
    generator = Generator.new(stages)

    # Expect the generated product to contain the string 'abcde' as code
    product = generator.generate
    expect(product.code).to eq('123456')
  end
end

################################################################################
#                                                                              #
# Helper methods and classes                                                   #
#                                                                              #
################################################################################

class TestAction
  def initialize(fragment)
    @fragment = fragment
  end

  def transform(product)
    product << fragment
  end
end
