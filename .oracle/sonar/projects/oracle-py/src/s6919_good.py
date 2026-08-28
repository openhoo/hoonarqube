class Net(keras.Model):
    def __init__(self, features):
        super().__init__()
        self.features = features
