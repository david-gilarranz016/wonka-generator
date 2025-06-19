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
end
