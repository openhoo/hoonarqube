import tensorflow as tf

scale = 2

@tf.function
def multiply(value):
    return value * scale
