"""
Конфигурационный файл для системы мониторинга угроз
"""

# Настройки API
API_KEYS = {
    'virustotal': 'YOUR_VIRUSTOTAL_API_KEY',  # Замените на реальный ключ
    'vulners': 'YOUR_VULNERS_API_KEY',        # Замените на реальный ключ
}

API_ENDPOINTS = {
    'virustotal_ip': 'https://www.virustotal.com/api/v3/ip_addresses/',
    'virustotal_domain': 'https://www.virustotal.com/api/v3/domains/',
    'vulners_search': 'https://vulners.com/api/v3/search/lucene/',
}

# Настройки анализа
THREAT_THRESHOLDS = {
    'cvss_score': 7.0,  # Пороговый балл CVSS для критических уязвимостей
    'suspicious_ports': [22, 23, 3389, 445, 1433],  # Подозрительные порты
    'dns_queries_threshold': 100,  # Порог DNS запросов для DDoS
    'failed_logins_threshold': 5,   # Порог неудачных попыток входа
}

# Настройки уведомлений
NOTIFICATION_SETTINGS = {
    'console_output': True,
    'simulate_blocking': True,
    'telegram_bot_token': 'YOUR_TELEGRAM_BOT_TOKEN',  # Опционально
    'telegram_chat_id': 'YOUR_CHAT_ID',               # Опционально
    'email_enabled': False,
}

# Пути для сохранения результатов
REPORT_PATH = 'reports/threat_report.json'
GRAPH_PATH = 'graphs/threat_analysis.png'
CSV_REPORT_PATH = 'reports/threat_report.csv'