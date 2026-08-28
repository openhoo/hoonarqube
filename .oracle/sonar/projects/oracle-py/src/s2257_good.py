def hash_password(pw):
    return sha256(pw).hexdigest()


def rot13_cipher(text):
    return codecs.encode(text, "rot13")
