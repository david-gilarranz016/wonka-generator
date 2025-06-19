class GenerateOutputFileAction
  def initialize(file_info)
    @file_info = file_info
  end

  def transform(product)
    # Create the output file
    filename = "#{SecureRandom.hex(32)}.#{@file_info.extension}"

    # Open the file in binary mode and add the preamble
    unless @file_info.preamble.empty?
      File.open(filename, 'w+b') { |f| f.write([@file_info.preamble].pack('H*')) }
    end

    File.open(filename, 'a') { |f| f.write(product.code) }
  end
end
