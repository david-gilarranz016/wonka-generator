class PhpObfuscator
  def obfuscate(code)
    obfuscated_code = ''

    # Remove comments, newlines and whitespace except after '<?php ' tag
    code.split("\n").each do |line|
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

    # Return the result of obfuscating all strings in the obfuscated code
    obfuscate_strings(obfuscated_code)
  end

  private

  def obfuscate_strings(code)
    processed_code = ''
    code = code.chars

    # Small finite state machine -> iterate through code. If string delimiter is found,
    # encode the following characters until the same delimiter is found again
    char = code.shift
    current_delimiter = nil
    until char.nil? 
      # Check if we are inside a string
      if current_delimiter.nil?
        # If not inside a string, check if a string should start
        current_delimiter = char if ['"', "'"].include? char 
      else
        # If inside a string, check if the current character closes the string
        if char == current_delimiter
          # If so, unset the inside-string flag
          current_delimiter = nil
        else
          # If not, encode the current character
          encoding = [:oct, :hex].sample
          char = encoding == :oct ? '\\%03o' % char.ord : '\\x%02x' % char.ord
        end
      end

      # Add the processed char to the string and continue
      processed_code << char
      char = code.shift
    end

    # Return the processed code
    processed_code
  end

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
