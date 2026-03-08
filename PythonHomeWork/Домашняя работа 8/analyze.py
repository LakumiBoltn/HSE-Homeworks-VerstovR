#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime

count = 0

def show_packet(packet):
    global count
    if IP not in packet or TCP not in packet or Raw not in packet:
        return
    count += 1
    payload = bytes(packet[Raw].load)
    try:
        decoded = payload.decode('utf-8', errors='ignore')
        if decoded.startswith('GET') or decoded.startswith('POST'):
            line = decoded.split('\r\n')[0]
            print(f"\n[{count}] REQUEST - {datetime.now().strftime('%H:%M:%S')}")
            print(f"    {line}")
        elif decoded.startswith('HTTP'):
            line = decoded.split('\r\n')[0]
            print(f"\n[{count}] RESPONSE - {datetime.now().strftime('%H:%M:%S')}")
            print(f"    {line}")
    except: pass

print("\n" + "="*60)
print("АНАЛИЗ ТРАФИКА GRUYERE")
print("="*60 + "\n")
try:
    sniff(prn=show_packet, filter="tcp port 443", store=False)
except KeyboardInterrupt:
    print(f"\n✅ Перехвачено: {count}")
except PermissionError:
    print("❌ sudo python3 analyze.py")
