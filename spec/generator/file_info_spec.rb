################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe FileInfo do
  it 'stores the file extension' do
    extension = 'php'
    run_stores_extension_scenario(extension)
  end

  it 'stores a different file extension' do
    extension = 'png'
    run_stores_extension_scenario(extension)
  end

  it 'can be created without a preamble (empty by default)' do
    file_info = FileInfo.new('php')
    expect(file_info.preamble).to eq('')
  end

  it 'stores the file preamble (magic bytes + other data)' do
    preamble = '474946' # Gif file magic bytes
    run_stores_preamble_scenario(preamble)
  end

  it 'stores a different file preamble' do
    # Create the preamble for a 1x1 white PNG'
    preamble = '89504e470d0a1a0a0000000d494844520000000100000001010000000037'\
               '6ef9240000000a4944415408d76368000000820081dd436af40000000049'\
               '454e44ae426082'
    run_stores_preamble_scenario(preamble)
  end
end

################################################################################
#                                                                              #
# Test scenarios to reduce test case code duplication                          #
#                                                                              #
################################################################################

def run_stores_extension_scenario(extension)
  # Create a new FileInfo object
  file_info = FileInfo.new(extension)

  # Check it has been stored
  expect(file_info.extension).to eq(extension)
end

def run_stores_preamble_scenario(preamble)
  # Create a new FileInfo object
  file_info = FileInfo.new('', preamble)

  # Check it has been stored
  expect(file_info.preamble).to eq(preamble)
end
