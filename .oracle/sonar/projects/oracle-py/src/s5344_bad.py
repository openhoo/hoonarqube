import hashlib


def hash_password(password_bytes):
    return hashlib.md5(password_bytes)
