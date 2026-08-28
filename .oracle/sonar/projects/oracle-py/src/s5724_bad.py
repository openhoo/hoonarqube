class C:
    @property
    def size(self, extra):
        return 1

    @size.setter
    def size(self):
        self._size = 0
