import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Настройка стиля
sns.set(style="darkgrid", palette="viridis")
plt.rcParams['figure.dpi'] = 300

# Загрузка данных (botsv1.json)
with open("botsv1.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Создание DataFrame из result
events = [item["result"] for item in data if "result" in item]
df = pd.DataFrame(events)

print("DataFrame готов!")
print(f"Размер: {df.shape[0]} событий, {len(df.columns)} полей")
print(f"sourcetype: {df['sourcetype'].value_counts().head(3).to_dict()}")

# График 1: Топ-10 EventCode (основное задание)
event_counts = df["EventCode"].value_counts().head(10).reset_index()
event_counts.columns = ["EventCode", "count"]

plt.figure(figsize=(12, 6))
sns.barplot(data=event_counts, x="EventCode", y="count")
plt.title("Топ-10 EventCode (EventID) в WinEventLog", fontsize=16, fontweight="bold")
plt.xlabel("EventCode", fontsize=12)
plt.ylabel("Количество событий", fontsize=12)
plt.xticks(rotation=45, ha="right")
plt.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig("top10_eventcode_dz11.png", dpi=300, bbox_inches="tight")
plt.show()

print("\nТоп-10 EventCode:")
print(event_counts)

# График 2: Топ-10 DNS-адресов (dest)
if "dest" in df.columns:
    top_dest = df["dest"].value_counts().head(10)
    
    plt.figure(figsize=(14, 6))
    sns.barplot(x=top_dest.index, y=top_dest.values)
    plt.title("Топ-10 DNS-адресов/домены (поле dest)", fontsize=16, fontweight="bold")
    plt.xlabel("Адрес/домен")
    plt.ylabel("Количество запросов")
    plt.xticks(rotation=45, ha="right")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig("top10_dns_dest_dz11.png", dpi=300, bbox_inches="tight")
    plt.show()
    
    print("\nТоп-10 dest:")
    print(top_dest)
else:
    print("Поле 'dest' не найдено")

# График 3: DNS-события (если есть)
dns_df = df[df["sourcetype"].str.contains("DNS", na=False, case=False)]
if not dns_df.empty:
    dns_events = dns_df["EventCode"].value_counts().head(10)
    plt.figure(figsize=(10, 5))
    sns.barplot(x=dns_events.index, y=dns_events.values, palette="plasma")
    plt.title("EventCode только в DNS-событиях")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("dns_only_events_dz11.png", dpi=300, bbox_inches="tight")
    plt.show()
    print(f"\nDNS-событий: {len(dns_df)}")
