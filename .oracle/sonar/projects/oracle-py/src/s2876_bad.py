class Bucket:
    def __iter__(self):
        return [1, 2, 3]


class Roster:
    def __iter__(self):
        return sorted(self.members)
