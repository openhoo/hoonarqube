import pandas as pd

frame = pd.read_csv("data.csv", dtype={"id": "int64"})
table = pd.read_table("data.tsv", dtype=str)
