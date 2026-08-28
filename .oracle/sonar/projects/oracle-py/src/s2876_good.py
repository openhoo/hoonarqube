class Bucket:
    def __iter__(self):
        return iter(self.items)


class Counter:
    def __iter__(self):
        yield from range(10)
