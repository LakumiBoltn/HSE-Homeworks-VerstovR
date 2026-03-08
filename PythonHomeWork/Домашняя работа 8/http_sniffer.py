from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse

def packet_handler(packet):
    if packet.haslayer(HTTPRequest):
        req = packet[HTTPRequest]
        print(f"HTTP Request: {req.Method.decode()} {req.Path.decode()}")
        print(f"Host: {req.Host.decode()}")
        print(f"From: {packet[IP].src}:{packet[TCP].sport}")
        print("-" * 50)
    
    elif packet.haslayer(HTTPResponse):
        resp = packet[HTTPResponse]
        print(f"HTTP Response: {resp.Status_Code.decode()} {resp.Status_Reason.decode()}")
        print(f"To: {packet[IP].dst}:{packet[TCP].dport}")
        print("-" * 50)

print("Запуск перехвата HTTP трафика...")
print("Откройте браузер и перейдите на http://httpbin.org/get")
print("Ctrl+C для остановки")

sniff(filter="tcp port 80 or tcp port 8080", prn=packet_handler, store=0)
