import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json

# Загрузка данных
with open('events.json', 'r') as f:
    data = json.load(f)['events']

df = pd.DataFrame(data)
print(df.head())  # данные

# График
plt.figure(figsize=(10, 6))
sns.countplot(data=df, x='signature')
plt.title('Количество событий по signature')
plt.xticks(rotation=90)
plt.show()