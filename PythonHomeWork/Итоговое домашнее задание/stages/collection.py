"""
stages/collection.py
--------------------
Этап 1 — Сбор данных.

Функции:
  - Запросы к VirusTotal v3 API для IP-адресов и доменов.
  - Парсинг JSON-логов событий Suricata в DataFrame.
"""

import json
import logging
import time
from pathlib import Path

import pandas as pd
import requests

from config import (
    VIRUSTOTAL_API_KEY,
    VT_BASE_URL,
    VT_RATE_LIMIT_DELAY,
    VT_TARGETS,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Внутренние вспомогательные функции
# ---------------------------------------------------------------------------

def _vt_get(endpoint):
    """Выполняет один аутентифицированный GET-запрос к VirusTotal v3 API."""
    if not VIRUSTOTAL_API_KEY:
        log.warning("VIRUSTOTAL_API_KEY не задан — пропуск запроса VT.")
        return None
    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}
    url = f"{VT_BASE_URL}/{endpoint}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        log.error("VT HTTP-ошибка для %s: %s", endpoint, exc)
    except requests.RequestException as exc:
        log.error("VT ошибка запроса для %s: %s", endpoint, exc)
    return None


# ---------------------------------------------------------------------------
# Проверки через VirusTotal
# ---------------------------------------------------------------------------

def vt_check_ip(ip):
    """Запрашивает у VirusTotal информацию по IPv4-адресу, возвращает нормализованную запись."""
    log.info("VT проверка -> IP: %s", ip)
    data = _vt_get(f"ip_addresses/{ip}")
    if data is None:
        return {"target": ip, "type": "ip", "source": "virustotal", "error": "нет данных"}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "target":     ip,
        "type":       "ip",
        "source":     "virustotal",
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "country":    attrs.get("country", "N/A"),
        "as_owner":   attrs.get("as_owner", "N/A"),
    }


def vt_check_domain(domain):
    """Запрашивает у VirusTotal информацию по домену, возвращает нормализованную запись."""
    log.info("VT проверка -> домен: %s", domain)
    data = _vt_get(f"domains/{domain}")
    if data is None:
        return {"target": domain, "type": "domain", "source": "virustotal",
                "error": "нет данных"}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "target":     domain,
        "type":       "domain",
        "source":     "virustotal",
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "registrar":  attrs.get("registrar", "N/A"),
        "country":    attrs.get("country", "N/A"),
    }


def vt_check_file(path):
    """Загружает файл в VirusTotal и возвращает результат анализа."""
    path = Path(path)
    if not path.exists():
        return {"target": str(path), "type": "file", "source": "virustotal",
                "error": "файл не найден"}
    log.info("VT проверка -> файл: %s", path)
    if not VIRUSTOTAL_API_KEY:
        log.warning("VIRUSTOTAL_API_KEY не задан — пропуск загрузки файла.")
        return {"target": str(path), "type": "file", "source": "virustotal",
                "error": "нет API-ключа"}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}
    try:
        with open(path, "rb") as fh:
            resp = requests.post(
                f"{VT_BASE_URL}/files",
                headers=headers,
                files={"file": (path.name, fh)},
                timeout=30,
            )
            resp.raise_for_status()
        analysis_id = resp.json().get("data", {}).get("id")
        # Ожидание результата (макс. 60 с)
        for _ in range(6):
            time.sleep(10)
            result = _vt_get(f"analyses/{analysis_id}")
            if result and result["data"]["attributes"].get("status") == "completed":
                stats = result["data"]["attributes"]["stats"]
                return {
                    "target":     str(path),
                    "type":       "file",
                    "source":     "virustotal",
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }
    except requests.RequestException as exc:
        return {"target": str(path), "type": "file", "source": "virustotal",
                "error": str(exc)}
    return {"target": str(path), "type": "file", "source": "virustotal",
            "error": "таймаут анализа"}


def collect_virustotal_data():
    """Проверяет все настроенные цели через VirusTotal с паузами для rate-limit."""
    results = []
    for idx, target in enumerate(VT_TARGETS):
        if target["type"] == "ip":
            record = vt_check_ip(target["value"])
        elif target["type"] == "domain":
            record = vt_check_domain(target["value"])
        else:
            log.warning("Неизвестный тип цели: %s", target["type"])
            continue
        results.append(record)
        if idx < len(VT_TARGETS) - 1:
            log.info("Пауза rate-limit: %d с ...", VT_RATE_LIMIT_DELAY)
            time.sleep(VT_RATE_LIMIT_DELAY)
    return results


# ---------------------------------------------------------------------------
# Парсер логов Suricata
# ---------------------------------------------------------------------------

def parse_suricata_logs(log_path):
    """
    Парсинг лог-файла Suricata Eve-JSON (формат JSONL) в DataFrame.
    Каждая строка файла — отдельный JSON-объект (стандарт Suricata).
    """
    log_path = Path(log_path)
    if not log_path.exists():
        log.error("Лог Suricata не найден: %s", log_path)
        return pd.DataFrame()

    events = []
    with open(log_path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                log.warning("Пропуск строки %d: %s", line_no, exc)

    if not events:
        return pd.DataFrame()

    df = pd.json_normalize(events, sep="_")
    df["timestamp"] = pd.to_datetime(df.get("timestamp"), errors="coerce", utc=True)
    log.info("Suricata: загружено %d событий из %s", len(df), log_path)
    return df
