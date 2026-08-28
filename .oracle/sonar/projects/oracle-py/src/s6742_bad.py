import pandas as pd

df = pd.read_csv("f.csv")
result = df.fillna(0).dropna().sort_values("a").head(20).reset_index().to_csv(index=False)
