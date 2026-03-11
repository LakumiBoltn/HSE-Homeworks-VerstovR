"""
Модуль для сбора данных из различных источников
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Any
import config


class DataCollector:
    """Класс для сбора данных из API и логов"""

    def __init__(self):
        self.api_keys = config.API_KEYS
        self.sources_used = []

    def collect_from_all_sources(self) -> Dict[str, Any]:
        """
        Сбор данных из всех доступных источников

        Returns:
            Dict с данными из различных источников
        """
        collected_data = {
            'timestamp': datetime.now().isoformat(),
            'sources': [],
            'data': {}
        }

        # Сбор из API VirusTotal (имитация для демонстрации)
        vt_data = self.collect_from_virustotal()
        if vt_data:
            collected_data['data']['virustotal'] = vt_data
            collected_data['sources'].append('virustotal_api')
            self.sources_used.append('API VirusTotal')

        # Сбор из API Vulners (имитация)
        vulners_data = self.collect_from_vulners()
        if vulners_data:
            collected_data['data']['vulners'] = vulners_data
            collected_data['sources'].append('vulners_api')
            self.sources_used.append('API Vulners')

        # Сбор из логов
        logs_data = self.collect_from_logs()
        if logs_data:
            collected_data['data']['logs'] = logs_data
            collected_data['sources'].append('security_logs')
            self.sources_used.append('Логи безопасности')

        return collected_data

    def collect_from_virustotal(self) -> List[Dict]:
        """
        Сбор данных из VirusTotal API (имитация для демонстрации)
        В реальном проекте здесь были бы реальные API запросы
        """
        # Имитация данных для демонстрации
        test_ips = ['8.8.8.8', '1.1.1.1', '185.130.5.133', '45.155.205.233']
        vt_results = []

        print("Подключение к VirusTotal API...")

        for ip in test_ips:
            # Имитация ответа от API
            result = {
                'ip': ip,
                'malicious': ip.endswith('133') or ip.endswith('233'),
                'suspicious': ip.endswith('1'),
                'harmless': not (ip.endswith('133') or ip.endswith('233') or ip.endswith('1')),
                'last_analysis_stats': {
                    'malicious': 3 if ip.endswith('133') else (2 if ip.endswith('233') else 0),
                    'suspicious': 1 if ip.endswith('1') else 0,
                    'harmless': 85,
                    'undetected': 10
                },
                'country': 'US' if ip.startswith('8') or ip.startswith('1') else 'RU',
                'as_owner': 'Google LLC' if ip.startswith('8') else 'CloudFlare' if ip.startswith('1') else 'Unknown'
            }
            vt_results.append(result)
            time.sleep(0.5)  # Имитация задержки API

        print(f"Получены данные по {len(vt_results)} IP адресам из VirusTotal")
        return vt_results

    def collect_from_vulners(self) -> List[Dict]:

        print("Подключение Vulners API...")

        # Имитация данных об уязвимостях
        vulnerabilities = [
            {
                'id': 'CVE-2024-1234',
                'title': 'Критическая уязвимость в Apache Log4j',
                'cvss_score': 9.8,
                'cvss_vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'description': 'Удаленное выполнение кода в Apache Log4j',
                'published': '2024-01-15',
                'affected_software': 'Apache Log4j <= 2.14.1'
            },
            {
                'id': 'CVE-2024-5678',
                'title': 'Уязвимость повышения привилегий в Windows',
                'cvss_score': 7.5,
                'cvss_vector': 'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                'description': 'Локальное повышение привилегий в Windows Kernel',
                'published': '2024-02-20',
                'affected_software': 'Windows 10/11'
            },
            {
                'id': 'CVE-2024-9012',
                'title': 'Межсайтовый скриптинг в WordPress',
                'cvss_score': 6.1,
                'cvss_vector': 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                'description': 'XSS уязвимость в плагине WordPress',
                'published': '2024-03-05',
                'affected_software': 'WordPress 5.x'
            }
        ]

        print(f" Получены данные о {len(vulnerabilities)} уязвимостях из Vulners")
        return vulnerabilities

    def collect_from_logs(self, log_file='sample_logs.json') -> Dict:
        """
        Сбор данных из файлов логов

        Args:
            log_file: путь к файлу с логами

        Returns:
            Dict с данными из логов
        """
        print(f" Чтение логов из файла {log_file}...")

        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                logs = json.load(f)
            print(f" Загружено {len(logs.get('events', []))} событий из логов")
            return logs
        except FileNotFoundError:
            print(f"Файл логов {log_file} не найден, создаю пример логов...")
            return self._create_sample_logs(log_file)

    def _create_sample_logs(self, log_file: str) -> Dict:

        sample_logs = {
            "events": [
                {
                    "timestamp": "2026-03-10T10:23:15Z",
                    "event_type": "suricata",
                    "src_ip": "192.168.1.100",
                    "dest_ip": "45.155.205.233",
                    "dest_port": 22,
                    "alert": {
                        "signature": "ET SCAN Potential SSH Scan",
                        "category": "Attempted Information Leak",
                        "severity": 2
                    }
                },
                {
                    "timestamp": "2026-03-10T10:24:30Z",
                    "event_type": "suricata",
                    "src_ip": "192.168.1.100",
                    "dest_ip": "45.155.205.233",
                    "dest_port": 23,
                    "alert": {
                        "signature": "ET SCAN Telnet Scan",
                        "category": "Attempted Information Leak",
                        "severity": 2
                    }
                },
                {
                    "timestamp": "2026-03-10T10:25:45Z",
                    "event_type": "suricata",
                    "src_ip": "10.0.0.50",
                    "dest_ip": "8.8.8.8",
                    "dest_port": 53,
                    "dns": {
                        "type": "query",
                        "rrname": "malware-domain.com",
                        "rdata": None
                    },
                    "alert": {
                        "signature": "ET MALWARE Known Malware Domain",
                        "category": "Malware Domain",
                        "severity": 1
                    }
                },
                {
                    "timestamp": "2026-03-10T10:30:00Z",
                    "event_type": "auth",
                    "user": "admin",
                    "src_ip": "203.0.113.45",
                    "status": "failed",
                    "message": "Failed login attempt"
                },
                {
                    "timestamp": "2026-03-10T10:30:05Z",
                    "event_type": "auth",
                    "user": "admin",
                    "src_ip": "203.0.113.45",
                    "status": "failed",
                    "message": "Failed login attempt"
                },
                {
                    "timestamp": "2026-03-10T10:30:10Z",
                    "event_type": "auth",
                    "user": "admin",
                    "src_ip": "203.0.113.45",
                    "status": "failed",
                    "message": "Failed login attempt"
                },
                {
                    "timestamp": "2026-03-10T10:30:15Z",
                    "event_type": "auth",
                    "user": "admin",
                    "src_ip": "203.0.113.45",
                    "status": "failed",
                    "message": "Failed login attempt"
                },
                {
                    "timestamp": "2026-03-10T10:30:20Z",
                    "event_type": "auth",
                    "user": "admin",
                    "src_ip": "203.0.113.45",
                    "status": "failed",
                    "message": "Failed login attempt"
                },
                {
                    "timestamp": "2026-03-10T10:35:00Z",
                    "event_type": "firewall",
                    "action": "blocked",
                    "src_ip": "198.51.100.67",
                    "dest_port": 445,
                    "protocol": "TCP",
                    "message": "Blocked SMB traffic from external IP"
                },
                {
                    "timestamp": "2026-03-10T10:40:00Z",
                    "event_type": "ids",
                    "src_ip": "192.168.1.150",
                    "dest_ip": "10.0.0.200",
                    "alert": {
                        "signature": "ET WEB_SERVER Possible SQL Injection Attempt",
                        "category": "Web Application Attack",
                        "severity": 1
                    }
                }
            ]
        }

        # Сохраняем пример логов
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(sample_logs, f, indent=2, ensure_ascii=False)
            print(f"Создан пример логов в файле {log_file}")
        except Exception as e:
            print(f"Ошибка при создании файла логов: {e}")

        return sample_logs

    def get_sources_used(self) -> List[str]:

        return self.sources_used