def collect(item, bucket=[]):
    bucket.append(item)
    return bucket


def fill(cache={}):
    cache["ready"] = True


def clamp(limit=10):
    limit = limit + 1
    return limit
