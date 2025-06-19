class FileInfo
  attr_reader :extension, :preamble

  def initialize(extension, preamble = '')
    @extension = extension
    @preamble = preamble
  end
end
