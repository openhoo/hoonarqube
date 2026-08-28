import numpy as np

score = 1.0

if score == np.nan:
    score = 0.0
if score != np.nan:
    score = 1.0
missing = score is np.nan
