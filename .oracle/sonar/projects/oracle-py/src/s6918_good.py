import tensorflow as tf

@tf.function
def build(x):
    weight = x
    return x * weight
