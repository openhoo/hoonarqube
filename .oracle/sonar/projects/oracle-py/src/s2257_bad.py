def xor_encrypt(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def weak_des(block, key):
    return block[0] ^ key[0]
