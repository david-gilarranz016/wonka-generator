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

  it 'stores the correct extension for a JPG file' do
    file_info = Output::JPG
    expect(file_info.extension).to eq('jpg')
  end

  it 'stores the correct preamble for a JPG file' do
    file_info = Output::JPG
    expect(file_info.preamble).to eq(
      'ffd8ffe000104a46494600010100000100010000ffdb0043000302020202'\
      '02030202020303030304060404040404080606050609080a0a090809090a'\
      '0c0f0c0a0b0e0b09090d110d0e0f101011100a0c12131210130f101010ff'\
      'c0000b080001000101011100ffc400140001000000000000000000000000'\
      '00000009ffc40014100100000000000000000000000000000000ffda0008'\
      '010100003f0054dfffd9'
    )
  end
end
