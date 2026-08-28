def __exit__(self, exc_type, exc_value, traceback):
    if exc_value is not None:
        raise exc_value
    return False
