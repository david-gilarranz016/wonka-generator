################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe PhpObfuscator do
  it 'removes newlines' do
    code = "<?php\nsystem($_GET['cmd']);\n ?>\n"
    run_removes_newlines_scenario(code)
  end

  it 'removes newlines from a different fragment' do
    code = "<?php\n\n\nsystem($_POST['cmd']);\n\n\n ?>\n"
    run_removes_newlines_scenario(code)
  end
end

################################################################################
#                                                                              #
# Test scenarios to reduce test case code duplication                          #
#                                                                              #
################################################################################

def run_removes_newlines_scenario(code)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  # Remove whitespaces from the supplied code
  expected_code = code.gsub(/\n/, '')
  expect(result).to eq(expected_code)
end
