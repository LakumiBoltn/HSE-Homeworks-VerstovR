from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime
import json

packets = []

def save_packet(pkt):
    try:
        if IP in pkt and TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            packets.append({
                'src': pkt[IP].src,
                'dst': pkt[IP].dst,
                'dport': pkt[TCP].dport,
                'size': len(payload),
                'time': datetime.now().isoformat()
            })
            print(f"Пакет {len(packets)} сохранён")
    except: pass

print("Анализ Gruyere трафика...")
print("Выполняй действия в браузере")
print("Нажми Ctrl+C\n")

try:
    sniff(prn=save_packet, filter="tcp", store=False, timeout=30)
except KeyboardInterrupt:
    pass

print(f"\nВсего пакетов: {len(packets)}")

with open('result.json', 'w') as f:
    json.dump(packets, f, indent=2)

print("Сохранено в result.json")
