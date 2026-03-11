"""
Модуль для анализа собранных данных и выявления угроз
"""

import pandas as pd
from typing import Dict, List, Any, Tuple
from collections import Counter
import config


class ThreatAnalyzer:
    """Класс для анализа угроз безопасности"""

    def __init__(self):
        self.thresholds = config.THREAT_THRESHOLDS
        self.threats_found = []
        self.analysis_results = {}

    def analyze_all_data(self, collected_data: Dict) -> Dict:
        """
        Анализ всех собранных данных

        Args:
            collected_data: данные из всех источников

        Returns:
            Dict с результатами анализа
        """
        print("\n Анализ данных на наличие угроз")

        analysis = {
            'timestamp': collected_data['timestamp'],
            'threats': [],
            'statistics': {}
        }

        # Анализ данных VirusTotal
        if 'virustotal' in collected_data['data']:
            vt_threats = self._analyze_virustotal(collected_data['data']['virustotal'])
            analysis['threats'].extend(vt_threats)
            analysis['statistics']['virustotal'] = len(vt_threats)

        # Анализ данных Vulners
        if 'vulners' in collected_data['data']:
            vuln_threats = self._analyze_vulners(collected_data['data']['vulners'])
            analysis['threats'].extend(vuln_threats)
            analysis['statistics']['vulners'] = len(vuln_threats)

        # Анализ логов
        if 'logs' in collected_data['data']:
            logs_threats = self._analyze_logs(collected_data['data']['logs'])
            analysis['threats'].extend(logs_threats)
            analysis['statistics']['logs'] = len(logs_threats)

        # Общая статистика
        analysis['statistics']['total_threats'] = len(analysis['threats'])
        analysis['statistics']['critical_threats'] = sum(
            1 for t in analysis['threats'] if t.get('severity') == 'CRITICAL'
        )
        analysis['statistics']['high_threats'] = sum(
            1 for t in analysis['threats'] if t.get('severity') == 'HIGH'
        )

        self.analysis_results = analysis
        self.threats_found = analysis['threats']

        print(f" Завершено, найдено угроз: {len(analysis['threats'])}")
        print(f"   - Критических: {analysis['statistics']['critical_threats']}")
        print(f"   - Высоких: {analysis['statistics']['high_threats']}")

        return analysis

    def _analyze_virustotal(self, vt_data: List[Dict]) -> List[Dict]:

        threats = []

        for item in vt_data:
            if item.get('malicious', False):
                threat = {
                    'source': 'VirusTotal',
                    'type': 'MALICIOUS_IP',
                    'severity': 'HIGH',
                    'description': f"IP адрес {item['ip']} обнаружен в базах вредоносных IP",
                    'details': {
                        'ip': item['ip'],
                        'malicious_votes': item['last_analysis_stats']['malicious'],
                        'country': item['country'],
                        'owner': item['as_owner']
                    },
                    'recommendation': 'Заблокировать IP адрес на межсетевом экране',
                    'timestamp': pd.Timestamp.now().isoformat()
                }
                threats.append(threat)

            elif item.get('suspicious', False):
                threat = {
                    'source': 'VirusTotal',
                    'type': 'SUSPICIOUS_IP',
                    'severity': 'MEDIUM',
                    'description': f"IP адрес {item['ip']} вызывает подозрения",
                    'details': {
                        'ip': item['ip'],
                        'suspicious_votes': item['last_analysis_stats']['suspicious'],
                        'country': item['country']
                    },
                    'recommendation': 'Проверить активность с этого IP',
                    'timestamp': pd.Timestamp.now().isoformat()
                }
                threats.append(threat)

        return threats

    def _analyze_vulners(self, vuln_data: List[Dict]) -> List[Dict]:

        threats = []
        cvss_threshold = self.thresholds['cvss_score']

        for vuln in vuln_data:
            if vuln['cvss_score'] >= cvss_threshold:
                severity = 'CRITICAL' if vuln['cvss_score'] >= 9.0 else 'HIGH'

                threat = {
                    'source': 'Vulners',
                    'type': 'VULNERABILITY',
                    'severity': severity,
                    'description': vuln['title'],
                    'details': {
                        'cve_id': vuln['id'],
                        'cvss_score': vuln['cvss_score'],
                        'cvss_vector': vuln['cvss_vector'],
                        'published': vuln['published'],
                        'affected_software': vuln['affected_software']
                    },
                    'recommendation': f"Немедленно обновить {vuln['affected_software']}",
                    'timestamp': pd.Timestamp.now().isoformat()
                }
                threats.append(threat)

        return threats

    def _analyze_logs(self, logs_data: Dict) -> List[Dict]:
        """
        Анализ логов на наличие угроз с безопасным доступом к ключам

        Args:
            logs_data: данные из логов

        Returns:
            List угроз из логов
        """
        threats = []
        events = logs_data.get('events', [])

        if not events:
            return threats

        # Анализ событий Suricata/IDS
        suricata_events = [e for e in events if e.get('event_type') == 'suricata' and 'alert' in e]
        for event in suricata_events:
            severity_map = {1: 'HIGH', 2: 'MEDIUM', 3: 'LOW'}
            alert_severity = severity_map.get(event['alert'].get('severity', 3), 'LOW')

            # Безопасное получение IP адресов
            src_ip = event.get('src_ip', 'unknown')
            dest_ip = event.get('dest_ip', 'unknown')
            dest_port = event.get('dest_port', 'N/A')

            threat = {
                'source': 'Suricata Logs',
                'type': 'IDS_ALERT',
                'severity': alert_severity,
                'description': event['alert']['signature'],
                'details': {
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'category': event['alert']['category']
                },
                'recommendation': 'Проверить источник и принять меры',
                'timestamp': event.get('timestamp', pd.Timestamp.now().isoformat())
            }
            threats.append(threat)

        # Анализ неудачных попыток входа
        failed_logins = [e for e in events if e.get('event_type') == 'auth' and e.get('status') == 'failed']
        if failed_logins:
            # Группируем по IP
            ip_counter = Counter()
            for event in failed_logins:
                ip = event.get('src_ip', 'unknown')
                ip_counter[ip] += 1

            for ip, count in ip_counter.items():
                if count >= self.thresholds['failed_logins_threshold'] and ip != 'unknown':
                    threat = {
                        'source': 'Auth Logs',
                        'type': 'BRUTE_FORCE_ATTEMPT',
                        'severity': 'HIGH',
                        'description': f"Обнаружено {count} неудачных попыток входа с IP {ip}",
                        'details': {
                            'src_ip': ip,
                            'attempts': count,
                            'threshold': self.thresholds['failed_logins_threshold']
                        },
                        'recommendation': f'Заблокировать IP {ip} на 24 часа',
                        'timestamp': pd.Timestamp.now().isoformat()
                    }
                    threats.append(threat)

        # Анализ подозрительных портов
        suspicious_ports = self.thresholds['suspicious_ports']
        port_events = [e for e in events if e.get('dest_port') in suspicious_ports]
        for event in port_events:
            src_ip = event.get('src_ip', 'unknown')
            dest_ip = event.get('dest_ip', 'unknown')
            dest_port = event.get('dest_port', 'N/A')

            threat = {
                'source': 'Network Logs',
                'type': 'SUSPICIOUS_PORT_ACCESS',
                'severity': 'MEDIUM',
                'description': f"Обнаружен доступ к подозрительному порту {dest_port}",
                'details': {
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'port': dest_port,
                    'protocol': event.get('protocol', 'TCP')
                },
                'recommendation': f'Проверить легитимность доступа к порту {dest_port}',
                'timestamp': event.get('timestamp', pd.Timestamp.now().isoformat())
            }
            threats.append(threat)

        # Анализ блокировок firewall
        blocked_events = [e for e in events if e.get('event_type') == 'firewall' and e.get('action') == 'blocked']
        for event in blocked_events:
            src_ip = event.get('src_ip', 'unknown')
            dest_port = event.get('dest_port', 'N/A')

            threat = {
                'source': 'Firewall Logs',
                'type': 'BLOCKED_THREAT',
                'severity': 'LOW',
                'description': event.get('message', 'Firewall blocked connection'),
                'details': {
                    'src_ip': src_ip,
                    'dest_port': dest_port,
                    'protocol': event.get('protocol', 'TCP')
                },
                'recommendation': 'Проанализировать источник для возможного добавления в черный список',
                'timestamp': event.get('timestamp', pd.Timestamp.now().isoformat())
            }
            threats.append(threat)

        # Анализ IDS событий
        ids_events = [e for e in events if e.get('event_type') == 'ids' and 'alert' in e]
        for event in ids_events:
            src_ip = event.get('src_ip', 'unknown')
            dest_ip = event.get('dest_ip', 'unknown')

            threat = {
                'source': 'IDS Logs',
                'type': 'IDS_ALERT',
                'severity': 'HIGH',
                'description': event['alert'].get('signature', 'Unknown IDS alert'),
                'details': {
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'category': event['alert'].get('category', 'Unknown')
                },
                'recommendation': 'Проверить атаку на веб-приложение',
                'timestamp': event.get('timestamp', pd.Timestamp.now().isoformat())
            }
            threats.append(threat)

        return threats

    def get_threats_for_visualization(self) -> Tuple[pd.DataFrame, Dict]:
        """
        Подготовка данных для визуализации

        Returns:
            Tuple[DataFrame, Dict]: DataFrame с угрозами и статистика
        """
        if not self.threats_found:
            return pd.DataFrame(), {}

        # Создаем DataFrame для анализа
        df = pd.DataFrame(self.threats_found)

        # Статистика для визуализации
        stats = {
            'by_source': df['source'].value_counts().to_dict(),
            'by_severity': df['severity'].value_counts().to_dict(),
            'by_type': df['type'].value_counts().to_dict()
        }

        return df, stats