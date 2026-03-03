"""
stages/
-------
Модули этапов конвейера:
  collection  — Этап 1: сбор данных через VirusTotal API + парсинг логов Suricata
  analysis    — Этап 2: оценка угроз
  response    — Этап 3: блокировка IP и уведомления
  reporting   — Этап 4: CSV/JSON-отчёты и диаграммы
"""
