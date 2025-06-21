class PhpObfuscator
  def obfuscate(code)
    obfuscated_code = ''

    code.split("\n").each do |line|
      # Remove comments, newlines and whitespace except after '<?php ' tag
      line.gsub!(%r{//.*$}, '')
      obfuscated_code << line.strip
    end
    obfuscated_code.sub!(/<\?php/, '<?php ')

    # Substitute all symbols with N-letter strings, where N is the minimum length required
    symbols = code.scan(/class \w+/).uniq.map { |match| match.to_s.sub('class ', '') }
    symbols += code.scan(/function \w+/).uniq.map { |match| match.to_s.sub('function ', '') }
    symbols += extract_variables(obfuscated_code)

    n = (symbols.length / 26.0).ceil
    pool = ('a' * n..'z' * n).to_a.shuffle

    symbols.each { |symbol| obfuscated_code.gsub!(/\b#{symbol}\b/, pool.pop.to_s) }

    obfuscated_code
  end

  private

  def extract_variables(code)
    # Extract all variables
    variable_names = code.scan(/\$\w+/).map { |match| match.to_s.sub('$', '') }
    variable_names += code.scan(/this->\w+/).map { |match| match.to_s.sub('this->', '') }
    variable_names.uniq!

    # Remove special variables this, $_GET, $_REQUEST, $_POST, etc. from the list
    variable_names.delete('this')
    variable_names.reject! { |var| var.match?(/_[A-Z]/) }

    variable_names
  end
end
