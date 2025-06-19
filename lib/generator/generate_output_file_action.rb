class GenerateOutputFileAction
  def initialize(file_info)
    @file_info = file_info
  end

  def transform(product)
    # Create the output file
    filename = SecureRandom.hex(32)
    File.open("#{filename}.#{@file_info.extension}", 'w') do |f|
      f.write(product.code)
    end
  end
end
