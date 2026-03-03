"""
stages/response.py
------------------
Этап 3 — Автоматическое реагирование.

Функции:
  - Имитация блокировки IP через iptables (без реальных системных вызовов).
  - Консольные уведомления (заглушка Telegram / e-mail).
  - Обработка угроз из DataFrame VirusTotal и Suricata.
"""

import logging

import pandas as pd

log = logging.getLogger(__name__)

# Реестр IP, заблокированных за текущий запуск
BLOCKED_IPS = set()


def simulate_block_ip(ip, reason):
    """Имитация блокировки IP через iptables — выводит команду, реальных действий нет."""
    if ip in BLOCKED_IPS or ip in ("N/A", ""):
        return
    BLOCKED_IPS.add(ip)
    print(f"  [BLOCK]  iptables -I INPUT -s {ip} -j DROP   # {reason}")


def send_notification(message):
    """Имитация отправки уведомления (заглушка Telegram / email)."""
    print(f"  [ALERT]  {message}")


def respond_to_vt_threats(df):
    """Реагирование на угрозы, выявленные VirusTotal."""
    if df.empty:
        return
    for _, row in df[df["is_threat"]].iterrows():
        send_notification(
            f"VirusTotal: {row['type']} '{row['target']}' — "
            f"malicious: {row['malicious']}, threat_score: {row['threat_score']}"
        )
        if row["type"] == "ip":
            simulate_block_ip(row["target"], f"VT malicious = {row['malicious']}")


def respond_to_suricata_threats(df):
    """Реагирование на угрозы, обнаруженные Suricata."""
    if df.empty:
        return
    for _, row in df.iterrows():
        send_notification(
            f"Suricata [{row['type']}] src={row['src_ip']} — {row['description']}"
        )
        if row["type"] in ("alert", "repeated_dns") and row["src_ip"] != "N/A":
            simulate_block_ip(row["src_ip"], row["description"])
