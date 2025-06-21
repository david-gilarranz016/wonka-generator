class PhpObfuscator
  def obfuscate(code)
    obfuscated_code = ''
    
    # Remove newlines and whitespace except after '<?php ' tag
    code.split("\n").each { |line| obfuscated_code << line.strip  }
    obfuscated_code.sub!(/<\?php/, '<?php ')

    obfuscated_code
  end
end
