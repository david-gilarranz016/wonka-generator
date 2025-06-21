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
    code = <<~PHP
    <?php
        class Test {}
    ?>
    PHP
    run_obfuscates_class_names_scenario(code)
  end
  
  it 'replaces class names with different random letters' do
    code = <<~PHP
    <?php
        class Test {}
        class DifferentTest {}
    ?>
    PHP
    run_obfuscates_class_names_scenario(code)
  end

  it 'replaces class names with 1-char strings' do
    code = <<~PHP
    <?php
        class Test1 {} class Test2 {} class Test3 {}
    ?>
    PHP
    run_symbol_length_scenario(code, 'class', 1) 
  end

  it 'replaces class names with 2-char strings' do
    code = <<~PHP
    <?php
        class Test01 {} class Test02 {} class Test03 {} class Test04 {} class Test05 {}
        class Test06 {} class Test07 {} class Test08 {} class Test09 {} class Test10 {}
        class Test11 {} class Test12 {} class Test13 {} class Test14 {} class Test15 {}
        class Test16 {} class Test17 {} class Test18 {} class Test19 {} class Test20 {}
        class Test21 {} class Test22 {} class Test23 {} class Test24 {} class Test25 {}
        class Test26 {} class Test27 {} class Test28 {} class Test29 {} class Test30 {}
    ?>
    PHP
    run_symbol_length_scenario(code, 'class', 2) 
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

def run_obfuscates_class_names_scenario(code)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  # Get all class name from the original and obfuscated code
  original_clases = code.scan(/class \w+/).map { |match| match.sub('class ', '') }
  obfuscated_clases = result.scan(/class \w+/).map { |match| match.sub('class ', '') }

  # Expect both sets to be different
  expect(original_clases).not_to eq(obfuscated_clases)
end

def run_symbol_length_scenario(code, symbol, length)
  # Create an obfuscator and obfuscate the code
  obfuscator = PhpObfuscator.new
  result = obfuscator.obfuscate(code)

  # Get all symbols of the specified type
  obfuscated_symbols = result.scan(/#{symbol} \w+/).map { |match| match.sub("#{symbol} ", '') }

  # Expect the length of all symbols to equal the expected length
  obfuscated_symbols.select! { |symbol| symbol.length != length }
  expect(obfuscated_symbols).to be_empty
end
