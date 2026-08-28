import tensorflow as tf

@tf.function
def multiply(value, factor):
    return value * factor
