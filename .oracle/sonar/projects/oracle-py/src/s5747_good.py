def load(data):
    try:
        return int(data)
    except ValueError:
        raise


def boom():
    raise ValueError("boom")
