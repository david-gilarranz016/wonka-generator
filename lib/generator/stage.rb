class Stage
  def initialize(actions)
    @actions = actions
  end

  def transform(product)
    @actions.each { |action| action.transform(product) }
  end
end
