import pandas as pd

raw = ["02/03/2024"]
stamps = pd.to_datetime(raw, format="%d/%m/%Y")
others = pd.to_datetime(raw, dayfirst=False)
