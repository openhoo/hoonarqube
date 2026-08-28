cipher = AES.new(key, AES.MODE_CBC, iv=b"0123456789abcdef")
encryptor = Cipher(algorithm, modes.CBC(b"staticiv12345"))
