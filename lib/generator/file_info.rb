class FileInfo
  attr_reader :extension

  def initialize(extension, preamble)
    @extension = extension
  end
end
