import tensorflow as tf

@tf.function
def compute(x):
    return compute(x - 1)
