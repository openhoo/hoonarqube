import tensorflow as tf

@tf.function
def compute(x):
    return x * 2
