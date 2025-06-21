class PhpObfuscator
  def obfuscate(code)
    obfuscated_code = ''

    # Remove newlines and whitespace except after '<?php ' tag
    code.split("\n").each { |line| obfuscated_code << line.strip  }
    obfuscated_code.sub!(/<\?php/, '<?php ')

    # Substitute all symbols with N-letter strings, where N is the minimum length required
    symbols = code.scan(/class \w+/).uniq.map { |match| match.sub('class ', '') }
    symbols += code.scan(/function \w+/).uniq.map { |match| match.sub('function ', '') }

    n = (symbols.length / 26.0).ceil
    pool = ("#{'a' * n}".."#{'z' * n}").to_a.shuffle

    symbols.each { |symbol| obfuscated_code.gsub!(/\b#{symbol}\b/, pool.pop) }

    obfuscated_code
  end
end
