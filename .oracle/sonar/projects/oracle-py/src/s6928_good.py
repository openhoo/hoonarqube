import tensorflow as tf

@tf.function
def train(data):
    return data * 2
