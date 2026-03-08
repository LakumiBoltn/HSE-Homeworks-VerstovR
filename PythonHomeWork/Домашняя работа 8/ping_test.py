from scapy.all import *

ans, unans = sr(IP(dst="google.com")/ICMP(), timeout=2, verbose=0)
for snd, rcv in ans:
    print(f"Ответ от {rcv[IP].src}: {rcv[ICMP].type}")
print(f"Ответов: {len(ans)}")
