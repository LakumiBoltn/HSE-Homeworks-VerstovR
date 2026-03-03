"""
config.py
---------
Центральная конфигурация: переменные окружения, константы, настройка логирования.
Все остальные модули импортируют настройки отсюда.
"""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# -- VirusTotal ----------------------------------------------------------------

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_RATE_LIMIT_DELAY = 15          # секунд между запросами (бесплатный тариф: 4/мин)
VT_MALICIOUS_THRESHOLD = 3        # порог: malicious >= этого значения → угроза

# Цели для проверки через VirusTotal
VT_TARGETS = [
    {"type": "ip",     "value": "185.220.101.45"},   # известный Tor-выход / сканер
    {"type": "ip",     "value": "194.165.16.11"},    # известный C2
    {"type": "ip",     "value": "91.92.109.14"},     # подозрительный
    {"type": "ip",     "value": "103.41.124.25"},    # источник brute-force
    {"type": "domain", "value": "malware.wicar.org"},
    {"type": "domain", "value": "google.com"},       # безопасный эталон
]

# -- Suricata ------------------------------------------------------------------

LOGS_DIR = Path("logs")
SURICATA_SEVERITY_THRESHOLD = 2   # 1 = наивысший, 3 = наименьший

# -- Отчёты --------------------------------------------------------------------

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

# -- Логирование ---------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
