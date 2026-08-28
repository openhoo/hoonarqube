strong_rsa = RSA.generate(4096)
strong_dsa = DSA.generate(3072)
strong_ec = ec.generate_private_key(ec.SECP384R1())
