class P:
    def __eq__(self, other):
        raise NotImplementedError

    def __hash__(self):
        raise NotImplementedError("use a real implementation")
