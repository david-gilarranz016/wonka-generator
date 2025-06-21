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

  it 'replaces class names with random letters' do
    code = '<?php class Test {} ?>'
    run_obfuscates_symbol_names_scenario(code, 'class')
  end

  it 'replaces class names with different random letters' do
    code = '<?php class Test {} class DifferentTest {} ?>'
    run_obfuscates_symbol_names_scenario(code, 'class')
  end

  it 'replaces class names with 1-char strings' do
    code = '<?php class Test1 {} class Test2 {} class Test3 {} ?>'
    run_symbol_length_scenario(code, 'class', 1)
  end

  it 'replaces class names with 2-char strings' do
    code = '<?php '
    30.times { |i| code << "class Test#{i} {} " }
    code << '?>'

    run_symbol_length_scenario(code, 'class', 2)
  end

  it 'replaces function names with random letters' do
    code = '<?php function Test {} ?>'
    run_obfuscates_symbol_names_scenario(code, 'function')
  end
  
  it 'replaces function names with different random letters' do
    code = '<?php function test {} function differentTest {} ?>'
    run_obfuscates_symbol_names_scenario(code, 'function')
  end

  it 'replaces function names with 1-char strings' do
    code = '<?php function test1 {} function test2 {} function test3 {} ?>'
    run_symbol_length_scenario(code, 'function', 1)
  end

  it 'replaces function names with 2-char strings' do
    code = '<?php '
    30.times { |i| code << "function test#{i} {} " }
    code << '?>'

    run_symbol_length_scenario(code, 'function', 2)
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

def run_obfuscates_symbol_names_scenario(code, symbol)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  # Get all symbol names from the original and obfuscated code
  original_symbols = code.scan(/#{symbol} \w+/).uniq.map { |match| match.sub("#{symbol} ", '') }
  obfuscated_symbols = result.scan(/#{symbol} \w+/).uniq.map { |match| match.sub("#{symbol} ", '') }

  # Expect both sets to be different
  expect(original_symbols).not_to eq(obfuscated_symbols)
end

def run_symbol_length_scenario(code, symbol, length)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  # Get all symbols of the specified type
  obfuscated_symbols = result.scan(/#{symbol} \w+/).uniq.map { |match| match.sub("#{symbol} ", '') }

  # Expect the length of all symbols to equal the expected length
  obfuscated_symbols.select! { |symbol| symbol.length != length }
  expect(obfuscated_symbols).to be_empty
end
