class P:
    def __eq__(self, other):
        return NotImplemented

    def __ne__(self, other):
        return not self.__eq__(other)
