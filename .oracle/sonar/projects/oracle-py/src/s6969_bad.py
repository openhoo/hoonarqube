from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

steps = [("scale", StandardScaler())]
pipe = Pipeline(steps)
