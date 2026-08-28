import math
import numpy as np

score = float("nan")

if math.isnan(score):
    score = 0.0
flagged = np.isnan(score)
positive = score > 0.0
