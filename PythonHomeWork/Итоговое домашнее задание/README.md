# Automated Threat Detection

Автоматизированное обнаружение и реагирование на сетевые угрозы.

## Описание

Скрипт выполняет четыре этапа:

1. **Сбор данных** — проверка IP-адресов и доменов через VirusTotal API, парсинг логов Suricata (`logs/eve.json`, формат JSONL).
2. **Анализ угроз** — оценка результатов VirusTotal (threat_score), выявление высокоприоритетных алертов и повторяющихся DNS-запросов в событиях Suricata.
3. **Реагирование** — имитация блокировки IP через iptables, консольные уведомления.
4. **Отчётность** — сохранение результатов в CSV/JSON, построение диаграмм (seaborn) в PNG.

Результаты сохраняются в папку `reports/`.

## Структура проекта

```
config.py          — конфигурация (API-ключи, пороги, пути)
main.py            — точка входа, оркестратор этапов
stages/
  collection.py    — сбор данных (VirusTotal API + парсинг Suricata)
  analysis.py      — анализ и оценка угроз
  response.py      — имитация блокировки и уведомления
  reporting.py     — CSV/JSON-отчёты и диаграммы
logs/
  eve.json         — лог Suricata (формат JSONL)
reports/           — генерируемые отчёты и диаграммы
```

## Запуск проекта

### 1. Клонирование репозитория

```bash
git clone <url-репозитория>
cd automated_thread_detection
```

### 2. Создание виртуального окружения и установка зависимостей

```bash
python -m venv venv
```

Активация:

- **Windows:** `venv\Scripts\activate`
- **Linux/macOS:** `source venv/bin/activate`

Установка зависимостей:

```bash
pip install -r requirements.txt
```

### 3. Настройка переменных окружения

Создайте файл `.env` в корне проекта:

```
VIRUSTOTAL_API_KEY=ваш_ключ_api
```

### 4. Запуск

```bash
python main.py
```

## Для разработки

После установки или обновления пакетов в venv — сохраните зависимости:

```bash
pip freeze > requirements.txt
```
