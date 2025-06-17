# frozen_string_literal: true

class Fragment
  attr_reader :key, :sources, :arguments

  def initialize(key, sources, arguments)
    @key = key
    @sources = sources
    @arguments = arguments
  end
end
