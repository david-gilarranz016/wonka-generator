class PhpObfuscator
  def obfuscate(code)
    # Remove newlines
    code.gsub(/\n/, '')
  end
end
