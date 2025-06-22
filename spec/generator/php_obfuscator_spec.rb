################################################################################
#                                                                              #
# Test cases                                                                   #
#                                                                              #
################################################################################

describe PhpObfuscator do
  it 'removes newlines' do
    code = "<?php\nsystem($_GET['.*']);\n?>\n"
    expected_code = /^<\?php system\(\$_GET\['.*'\]\);\?>$/
    run_removes_newlines_scenario(code, expected_code)
  end

  it 'removes newlines from a different fragment' do
    code = "<?php\n\n\nsystem($_POST['cmd']);\n?>\n"
    expected_code = /^<\?php system\(\$_POST\['.*'\]\);\?>$/
    run_removes_newlines_scenario(code, expected_code)
  end

  it 'removes whitespace' do
    code = "<?php\n    system($_GET['cmd']);\n ?>\n"
    expected_code = /^<\?php system\(\$_GET\['.*'\]\);\?>$/
    run_removes_whitespace_scenario(code, expected_code)
  end

  it 'removes whitespace from a different fragment' do
    code = "<?php\n\n\n\t   system($_POST['cmd']);\n  \n\t\n ?>\n"
    expected_code = /^<\?php system\(\$_POST\['.*'\]\);\?>$/
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

  it 'replaces variable names with random letters' do
    code = '<?php $var = 1; ?>'
    run_obfuscates_variable_names_scenario(code)
  end

  it 'replaces variable names with different random letters' do
    code = '<?php class Test { $attr = 1; _construct($arg) { $this->attr = $arg; } } ?>'
    run_obfuscates_variable_names_scenario(code)
  end

  it 'replaces variable names with 1-char strings' do
    code = '<?php $test1 = 1; $test2 = 2; $this->test3 = 3 ?>'
    run_variable_length_scenario(code, 1)
  end

  it 'replaces variable names with 2-char strings' do
    code = '<?php '
    30.times { |i| code << "$test#{i} = #{i};" }
    code << '?>'

    run_variable_length_scenario(code, 2)
  end

  it 'removes comments' do
    code = "<?php\n// Comment\n?>"
    run_removes_comments_scenario(code, ['// Comment'])
  end

  it 'removes different comment' do
    code = "<?php\n// Different comment\n$variable = 3; // Second comment\n?>"
    run_removes_comments_scenario(code, ['// Different comment', '// Second comment'])
  end

  it 'obfuscates string literals' do
    code = '<?php $var = "string";?>'
    encoding = [:oct, :oct, :oct, :hex, :hex, :oct]
    delimiter = '"'
    run_obfuscates_single_string_scenario(code, encoding, delimiter)
  end

  it 'obfuscates different string literals' do
    code = "<?php $var = 'string';?>"
    encoding = [:hex, :oct, :hex, :hex, :oct, :hex]
    delimiter = "'"
    run_obfuscates_single_string_scenario(code, encoding, delimiter)
  end

  it 'obfuscates interlaced string literals' do
    code = "<?php $var1 = '\"string\"';?>"
    encoding = [:hex, :oct, :oct, :hex, :oct, :hex, :hex, :hex]
    delimiter = "'"
    run_obfuscates_single_string_scenario(code, encoding, delimiter)
  end

  it 'obfuscates different interlaced string literals' do
    code = '<?php $var1 = "\'string\'";?>'
    delimiter = '"'
    encoding = [:oct, :hex, :hex, :hex, :oct, :oct, :hex, :oct]
    run_obfuscates_single_string_scenario(code, encoding, delimiter)
  end

  it 'replaces namespace names with random letters' do
    code = '<?php namespace Test; ?>'
    run_obfuscates_symbol_names_scenario(code, 'namespace')
  end

  it 'replaces namespace names with different random letters' do
    code = '<?php namespace Test; namespace DifferentTest; ?>'
    run_obfuscates_symbol_names_scenario(code, 'namespace')
  end

  it 'replaces namespace names with 1-char strings' do
    code = '<?php namespace Test1; namespace Test2; namespace Test3; ?>'
    run_symbol_length_scenario(code, 'namespace', 1)
  end

  it 'replaces namespace names with 2-char strings' do
    code = '<?php '
    30.times { |i| code << "namespace Test#{i}; " }
    code << '?>'

    run_symbol_length_scenario(code, 'namespace', 2)
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

  expect(result).to match(expected_code)
end

def run_removes_whitespace_scenario(code, expected_code)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  expect(result).to match(expected_code)
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
  obfuscated_symbols.reject! { |symbol| symbol.length == length }
  expect(obfuscated_symbols).to be_empty
end

def run_obfuscates_variable_names_scenario(code)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  # Get all variables (except the keyword $this)
  original_variables = extract_variables(code)
  obfuscated_variables = extract_variables(result)

  # Expect arrays to be different
  expect(obfuscated_variables).not_to eq(original_variables)
end

def run_variable_length_scenario(code, length)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  # Get all variables
  variables = extract_variables(result)

  # Expect the length of all symbols to equal the expected length
  variables.reject! { |var| var.length == length }
  expect(variables).to be_empty
end

def run_removes_comments_scenario(code, comments)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  # Expect the result not to contain the comments
  includes_comments = comments.any? { |comment| result.match? comment }
  expect(includes_comments).to be_falsy
end

def run_obfuscates_single_string_scenario(code, encoding, delimiter)
  # Mock Array.sample to return the supplied values
  return_values = encoding.clone
  allow_any_instance_of(Array).to receive(:sample) { return_values.shift }

  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)
  encoded_string = result.match(/#{delimiter}.*#{delimiter}/).to_s.gsub(delimiter, '')

  # Build the expected string based on encoding
  expected_string = ''
  string = code.match(/#{delimiter}.*#{delimiter}/).to_s.gsub(delimiter, '')
  string.bytes.zip(encoding).each do |character, encoding|
    encoded_char = encoding == :oct ? '\\%03o' % character : '\\x%02x' % character
    expected_string << encoded_char
  end

  # Compare both strings
  expect(encoded_string).to eq(expected_string)
end

################################################################################
#                                                                              #
# Helper functions                                                             #
#                                                                              #
################################################################################

def extract_variables(code)
  variable_names = code.scan(/\$\w+/).map { |match| match.sub('$', '') }
  variable_names += code.scan(/this->\w+/).map { |match| match.sub('this->', '') }
  variable_names = variable_names.uniq
  variable_names.delete('this')

  variable_names
end

