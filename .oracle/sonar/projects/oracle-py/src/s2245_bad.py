def issue_token(user):
    return random.randint(0, 999999)


def new_password(length):
    return "".join(random.choice("abcdefgh23456789") for _ in range(length))
