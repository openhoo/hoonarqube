def parse(value):
    try:
        return int(value)
    except ValueError:
        return 0
    except TypeError:
        return 1
