def collect(item, bucket=None):
    if bucket is None:
        bucket = []
    bucket.append(item)
    return bucket


def clamp(limit=10):
    adjusted = limit + 1
    return adjusted
