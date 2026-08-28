pw = b"secret"

hashlib.pbkdf2_hmac("sha256", pw, b"salt", 100000)
hashlib.scrypt(pw, salt=b"staticsalt")
