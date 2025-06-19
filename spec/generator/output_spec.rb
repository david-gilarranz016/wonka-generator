################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe Output do
  it 'stores the correct extension for a PHP file' do
    file_info = Output::PHP
    expect(file_info.extension).to eq('php')
  end

  it 'stores the correct preamble for a PHP file' do
    file_info = Output::PHP
    expect(file_info.preamble).to be_empty
  end

  it 'stores the correct extension for a GIF file' do
    file_info = Output::GIF
    expect(file_info.extension).to eq('gif')
  end

  it 'stores the correct preamble for a GIF file' do
    file_info = Output::GIF
    expect(file_info.preamble).to eq('474946')
  end

  it 'stores the correct extension for a PNG file' do
    file_info = Output::PNG
    expect(file_info.extension).to eq('png')
  end

  it 'stores the correct preamble for a PNG file' do
    file_info = Output::PNG
    expect(file_info.preamble).to eq(
      '89504e470d0a1a0a0000000d494844520000000100000001010000000037'\
      '6ef9240000000a4944415408d76368000000820081dd436af40000000049'\
      '454e44ae426082'
    )
  end
end
