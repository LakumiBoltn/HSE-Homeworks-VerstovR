"""
stages/analysis.py
------------------
Этап 2 — Анализ угроз.

Функции:
  - Оценка записей VirusTotal и выявление угроз.
  - Обнаружение угроз в событиях Suricata (высокоприоритетные алерты, повторяющиеся DNS).
"""

import logging

import pandas as pd

from config import VT_MALICIOUS_THRESHOLD, SURICATA_SEVERITY_THRESHOLD

log = logging.getLogger(__name__)


def analyse_virustotal(records):
    """
    Преобразует сырые записи VT в DataFrame с оценками.
    threat_score = malicious * 2 + suspicious.
    is_threat    = malicious >= VT_MALICIOUS_THRESHOLD.
    """
    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    df["malicious"] = pd.to_numeric(df["malicious"], errors="coerce").fillna(0).astype(int) if "malicious" in df.columns else 0
    df["suspicious"] = pd.to_numeric(df["suspicious"], errors="coerce").fillna(0).astype(int) if "suspicious" in df.columns else 0
    df["threat_score"] = df["malicious"] * 2 + df["suspicious"]
    df["is_threat"] = df["malicious"] >= VT_MALICIOUS_THRESHOLD
    df.sort_values("threat_score", ascending=False, inplace=True)
    return df.reset_index(drop=True)


def analyse_suricata(df):
    """
    Обнаружение угроз в событиях Suricata:
      - Алерты высокой серьёзности (severity <= порога).
      - Повторяющиеся DNS-запросы к одному домену (возможный DGA / C2-маяк).
    Возвращает сводный DataFrame угроз.
    """
    if df.empty:
        return pd.DataFrame()

    threats = []

    # Правило 1: алерты с серьёзностью <= порога
    alerts = df[df["event_type"] == "alert"].copy()
    if not alerts.empty and "alert_severity" in alerts.columns:
        alerts["alert_severity"] = pd.to_numeric(alerts["alert_severity"], errors="coerce")
        high = alerts[alerts["alert_severity"] <= SURICATA_SEVERITY_THRESHOLD]
        for _, row in high.iterrows():
            threats.append({
                "source":      "suricata",
                "type":        "alert",
                "src_ip":      row.get("src_ip", "N/A"),
                "dest_ip":     row.get("dest_ip", "N/A"),
                "description": row.get("alert_signature", "N/A"),
                "severity":    int(row.get("alert_severity", 0)),
                "timestamp":   str(row.get("timestamp", "")),
                "is_threat":   True,
            })

    # Правило 2: повторяющиеся DNS-запросы (>= 3 к одному домену)
    dns_events = df[df["event_type"] == "dns"].copy()
    if not dns_events.empty and "dns_rrname" in dns_events.columns:
        dns_counts = (
            dns_events.groupby(["src_ip", "dns_rrname"])
            .size()
            .reset_index(name="query_count")
        )
        repeated = dns_counts[dns_counts["query_count"] >= 3]
        for _, row in repeated.iterrows():
            threats.append({
                "source":      "suricata",
                "type":        "repeated_dns",
                "src_ip":      row["src_ip"],
                "dest_ip":     "N/A",
                "description": f"Повтор DNS -> {row['dns_rrname']} ({row['query_count']}x)",
                "severity":    2,
                "timestamp":   "N/A",
                "is_threat":   True,
            })

    return pd.DataFrame(threats)
