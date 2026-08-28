pw = b"secret"

hashlib.pbkdf2_hmac("sha256", pw, os.urandom(32), 100000)
hashlib.pbkdf2_hmac("sha256", pw, b"a-32-byte-salt-of-random-data!!", 100000)
