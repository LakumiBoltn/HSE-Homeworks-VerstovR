import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Настройка стиля
sns.set(style="darkgrid", palette="viridis")
plt.rcParams['figure.dpi'] = 300

# Загрузка и подготовка данных
with open("botsv1.json", "r", encoding="utf-8") as f:
    df = pd.DataFrame([item["result"] for item in json.load(f) if "result" in item])

print(f"Загружено событий: {len(df)}, полей: {len(df.columns)}")
print(f"Типы логов: {df['sourcetype'].value_counts().to_dict()}")

def plot_top10(data, column, title, filename, xlabel=None):
    """Универсальная функция для построения топ-10 графиков."""
    top10 = data.value_counts().head(10)
    plt.figure(figsize=(12, 6))
    sns.barplot(x=top10.index, y=top10.values)
    plt.title(title, fontsize=16, fontweight="bold")
    plt.xlabel(xlabel or column, fontsize=12)
    plt.ylabel("Количество", fontsize=12)
    plt.xticks(rotation=45, ha="right")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches="tight")
    plt.show()
    return top10

# График 1: Топ-10 EventCode для WinEventLog
win_df = df[df["sourcetype"] == "WinEventLog"]
if not win_df.empty:
    top_events = plot_top10(win_df["EventCode"], "EventCode",
                           "Топ-10 EventCode (WinEventLog)", "top10_eventcode.png")
    print("\nТоп-10 EventCode в WinEventLog:\n", top_events)

# График 2: Топ-10 DNS-адресов
if "dest" in df.columns:
    top_dest = plot_top10(df["dest"].dropna(), "dest",
                         "Топ-10 DNS-адресов/доменов", "top10_dest.png", "Адрес/домен")
    print("\nТоп-10 DNS-адресов:\n", top_dest)

# График 3: DNS-события (если есть)
dns_df = df[df["sourcetype"].str.contains("DNS", na=False, case=False)]
if not dns_df.empty:
    top_dns = plot_top10(dns_df["EventCode"], "EventCode",
                        "Топ-10 EventCode в DNS-логах", "top10_dns_events.png")
    print(f"\nDNS-событий: {len(dns_df)}")
    print("Топ-10 EventCode в DNS:\n", top_dns)