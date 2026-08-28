import pandas as pd

df = pd.read_csv("f.csv")
tidy = df.fillna(0).dropna().head()
