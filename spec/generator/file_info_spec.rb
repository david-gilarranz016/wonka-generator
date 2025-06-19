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
end

################################################################################
#                                                                              #
# Test scenarios to reduce test case code duplication                          #
#                                                                              #
################################################################################

def run_stores_extension_scenario(extension)
  # Create a new FileInfo object
  file_info = FileInfo.new(extension, '')

  # Check it has been stored
  expect(file_info.extension).to eq(extension)
end
