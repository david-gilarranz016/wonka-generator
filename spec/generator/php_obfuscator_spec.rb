################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe PhpObfuscator do
  it 'removes newlines' do
    code = "<?php\nsystem($_GET['cmd']);\n?>\n"
    expected_code = "<?php system($_GET['cmd']);?>"
    run_removes_newlines_scenario(code, expected_code)
  end

  it 'removes newlines from a different fragment' do
    code = "<?php\n\n\nsystem($_POST['cmd']);\n?>\n"
    expected_code = "<?php system($_POST['cmd']);?>"
    run_removes_newlines_scenario(code, expected_code)
  end

  it 'removes whitespace' do
    code = "<?php\n    system($_GET['cmd']);\n ?>\n"
    expected_code = "<?php system($_GET['cmd']);?>"
    run_removes_whitespace_scenario(code, expected_code)
  end

  it 'removes whitespace from a different fragment' do
    code = "<?php\n\n\n\t   system($_POST['cmd']);\n  \n\t\n ?>\n"
    expected_code = "<?php system($_POST['cmd']);?>"
    run_removes_whitespace_scenario(code, expected_code)
  end
end

################################################################################
#                                                                              #
# Test scenarios to reduce test case code duplication                          #
#                                                                              #
################################################################################

def run_removes_newlines_scenario(code, expected_code)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  expect(result).to eq(expected_code)
end

def run_removes_whitespace_scenario(code, expected_code)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  expect(result).to eq(expected_code)
end
