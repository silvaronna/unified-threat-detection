import pandas as pd

df = pd.read_parquet('train.parquet')
print(df.head())