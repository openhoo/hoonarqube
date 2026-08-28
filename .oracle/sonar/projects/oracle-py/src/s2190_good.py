def countdown(depth):
    if depth <= 0:
        return 0
    return countdown(depth - 1)
