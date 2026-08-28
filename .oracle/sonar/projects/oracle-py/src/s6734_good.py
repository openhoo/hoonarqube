import pandas as pd

df = pd.DataFrame({"a": [1, None, 3]})
df = df.fillna(0)
df = df.sort_values("a")
