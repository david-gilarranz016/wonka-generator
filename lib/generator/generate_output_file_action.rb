class GenerateOutputFileAction
  def initialize(file_info)
    @file_info = file_info
  end

  def transform(product)
    # Create the output file
    path = "public/output/#{SecureRandom.hex(32)}.#{@file_info.extension}"

    # Open the file in binary mode and add the preamble
    unless @file_info.preamble.empty?
      File.open(path, 'w+b') { |f| f.write([@file_info.preamble].pack('H*')) }
    end

    # Append the code to the file
    File.open(path, 'a') { |f| f.write(product.code) }

    # Update the product with the output path for the filename and the checksum
    product.file = path.delete_prefix('public/')
    product.checksum = OpenSSL::Digest::SHA256.file(path).hexdigest
  end
end
