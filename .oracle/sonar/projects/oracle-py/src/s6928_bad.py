import tensorflow as tf

@tf.function
def train(data):
    print("training")
    assert data is not None
    return data
