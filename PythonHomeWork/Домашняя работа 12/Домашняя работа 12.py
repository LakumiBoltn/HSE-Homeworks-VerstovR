import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import asyncio

pcap_file = r"C:\Users\User\Desktop\Python\maga\12\dhcp.pcapng"

# Создаем event loop для pyshark
try:
    loop = asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

# Читаем все пакеты
cap = pyshark.FileCapture(pcap_file)

packet_data = []
protocols = []
ips = []

for pkt in cap:
    try:
        time = pkt.sniff_time
        protocol = pkt.highest_layer
        
        # Пытаемся получить IP адреса
        src_ip = "N/A"
        dst_ip = "N/A"
        if hasattr(pkt, 'ip'):
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            ips.extend([src_ip, dst_ip])
        elif hasattr(pkt, 'ipv6'):
            src_ip = pkt.ipv6.src
            dst_ip = pkt.ipv6.dst
            ips.extend([src_ip, dst_ip])
        
        packet_data.append((time, protocol, src_ip, dst_ip))
        protocols.append(protocol)
        
    except AttributeError:
        continue

cap.close()

# --- Анализ ---
if packet_data:
    df = pd.DataFrame(packet_data, columns=["time", "protocol", "src_ip", "dst_ip"])
    df['time'] = pd.to_datetime(df['time'])
    
    print(f"Всего пакетов: {len(df)}")
    
    # Топ протоколов
    print("\nТоп протоколов:")
    for proto, count in Counter(protocols).most_common(10):
        print(f"{proto}: {count}")
    
    # Топ IP-адресов
    print("\nТоп IP-адресов:")
    for ip, count in Counter(ips).most_common(5):
        print(f"{ip}: {count}")
    
    # График по времени
    df['minute'] = df['time'].dt.floor('min')
    packets_by_time = df.groupby('minute').size()
    
    plt.figure(figsize=(12, 6))
    packets_by_time.plot(kind='line')
    plt.title("Все пакеты по времени")
    plt.xlabel("Время")
    plt.ylabel("Количество пакетов")
    plt.grid(True, alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
    
    # Сохраняем результаты
    df.to_csv("packet_analysis.csv", index=False)
    print("\nРезультаты сохранены в packet_analysis.csv")
    
else:
    print("Не удалось прочитать пакеты из файла")