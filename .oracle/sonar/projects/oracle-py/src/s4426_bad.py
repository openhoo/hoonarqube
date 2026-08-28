weak_rsa = RSA.generate(1024)
weak_dsa = DSA.generate(512)
small_ec = ec.generate_private_key(ec.SECP192R1())
weaker_ec = ec.generate_private_key(ec.SECP224R1())
