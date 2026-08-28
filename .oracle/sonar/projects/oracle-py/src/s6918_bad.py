import tensorflow as tf

Variable = object

@tf.function
def build(x):
    weight = Variable(1.0)
    return x * weight
