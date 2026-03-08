#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP
from datetime import datetime

count = 0

def show_packet(packet):
    global count
    if IP not in packet or TCP not in packet:
        return
    
    count += 1
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    
    print(f"\n[{count}] {datetime.now().strftime('%H:%M:%S')} TCP")
    print(f"    {ip_src}:{sport} -> {ip_dst}:{dport}")

print("\n" + "="*70)
print("АНАЛИЗ ТРАФИКА GRUYERE")
print("="*70)
print("\nПерехватываем пакеты портов 80 и 443")
print("Откройте Gruyere и выполняйте действия\n")

try:
    sniff(prn=show_packet, filter="tcp port 80 or tcp port 443", store=False)
except KeyboardInterrupt:
    print(f"\n\n✅ Перехвачено пакетов: {count}")
