class C:
    @property
    def size(self):
        return 1

    @size.setter
    def size(self, value):
        self._size = value
