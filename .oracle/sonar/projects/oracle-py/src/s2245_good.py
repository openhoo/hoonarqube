def issue_token(user):
    return secrets.token_hex(32)


def stats(sample):
    return random.randint(0, 10)
