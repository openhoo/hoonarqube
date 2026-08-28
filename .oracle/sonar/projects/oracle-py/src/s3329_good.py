cipher = AES.new(key, AES.MODE_CBC, iv=os.urandom(16))
encryptor = Cipher(algorithm, modes.CBC(next_iv()))
