#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime
import json

all_packets = []

def capture(packet):
    if IP not in packet or TCP not in packet:
        return
    
    try:
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            all_packets.append({
                'time': datetime.now().isoformat(),
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'dport': packet[TCP].dport,
                'size': len(payload)
            })
            print(f"[{len(all_packets)}] пакет")
    except:
        pass

print("Захват трафика Gruyere...")
print("Нажми Ctrl+C для остановки\n")

try:
    sniff(prn=capture, filter="tcp port 443", store=False)
except KeyboardInterrupt:
    print(f"\n✅ Всего пакетов: {len(all_packets)}")
    with open('packets.json', 'w') as f:
        json.dump(all_packets, f, indent=2)
    print("✅ Сохранено в packets.json")
