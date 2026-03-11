import time
from datetime import datetime
from typing import List, Dict, Any
import config


class ThreatResponder:

    def __init__(self):
        self.settings = config.NOTIFICATION_SETTINGS
        self.responses = []
        self.blocked_ips = set()
        self.notifications_sent = 0

    def respond_to_threats(self, threats: List[Dict]) -> List[Dict]:

        print("\n Реагирование на угрозы...")

        if not threats:
            print(" Угроз не обнаружено, реагирование не требуется")
            return []

        # Сортируем угрозы по серьезности
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_threats = sorted(
            threats,
            key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4)
        )

        for threat in sorted_threats:
            response = self._handle_threat(threat)
            self.responses.append(response)

            # Имитация задержки между действиями
            time.sleep(0.5)

        print(f"\n Итоги реагирования:")
        print(f"   - Заблокировано IP: {len(self.blocked_ips)}")
        print(f"   - Отправлено уведомлений: {self.notifications_sent}")
        print(f"   - Обработано угроз: {len(self.responses)}")

        return self.responses

    def _handle_threat(self, threat: Dict) -> Dict:

        response = {
            'threat_id': id(threat),
            'threat_type': threat['type'],
            'severity': threat['severity'],
            'timestamp': datetime.now().isoformat(),
            'actions_taken': []
        }

        # Вывод в консоль (всегда)
        if self.settings['console_output']:
            self._console_notification(threat)
            response['actions_taken'].append('console_notification')

        # Имитация блокировки для определенных типов угроз
        if self.settings['simulate_blocking']:
            blocking_result = self._simulate_blocking(threat)
            if blocking_result:
                response['actions_taken'].append('ip_blocking')
                response['blocking_details'] = blocking_result

        # Имитация отправки в Telegram
        if self.settings.get('telegram_bot_token') != 'YOUR_TELEGRAM_BOT_TOKEN':
            self._simulate_telegram(threat)
            response['actions_taken'].append('telegram_notification')
            self.notifications_sent += 1

        # Имитация отправки email
        if self.settings['email_enabled']:
            self._simulate_email(threat)
            response['actions_taken'].append('email_notification')
            self.notifications_sent += 1

        return response

    def _console_notification(self, threat: Dict):

        severity_colors = {
            'CRITICAL': '\033[91m',  # Красный
            'HIGH': '\033[93m',  # Желтый
            'MEDIUM': '\033[94m',  # Синий
            'LOW': '\033[92m'  # Зеленый
        }
        reset_color = '\033[0m'

        color = severity_colors.get(threat['severity'], '\033[0m')

        print(f"\n{color} ОБНАРУЖЕНА УГРОЗА [{threat['severity']}]{reset_color}")
        print(f"   Тип: {threat['type']}")
        print(f"   Описание: {threat['description']}")
        print(f"   Источник: {threat['source']}")
        print(f"   Рекомендация: {threat['recommendation']}")

        # Детальная информация
        if threat['severity'] in ['CRITICAL', 'HIGH']:
            print(f"   {color} ТРЕБУЕТСЯ НЕМЕДЛЕННОЕ ВМЕШАТЕЛЬСТВО!{reset_color}")

    def _simulate_blocking(self, threat: Dict) -> Dict:

        blocking_info = {}

        # Извлекаем IP из различных полей угрозы
        ip_to_block = None

        if 'details' in threat:
            if 'ip' in threat['details']:
                ip_to_block = threat['details']['ip']
            elif 'src_ip' in threat['details']:
                ip_to_block = threat['details']['src_ip']

        if ip_to_block and ip_to_block not in self.blocked_ips:
            # Имитация блокировки на firewall
            print(f" ИМИТАЦИЯ: Блокировка IP {ip_to_block} на межсетевом экране")
            self.blocked_ips.add(ip_to_block)

            blocking_info = {
                'blocked_ip': ip_to_block,
                'method': 'firewall_rule',
                'duration': '24 hours',
                'rule_id': f"BLK-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            }
        elif ip_to_block:
            print(f" IP {ip_to_block} уже заблокирован")

        return blocking_info

    def _simulate_telegram(self, threat: Dict):

        print(f" ИМИТАЦИЯ: Отправка уведомления в Telegram об угрозе {threat['type']}")
        # В реальном проекте здесь был бы код отправки через Telegram Bot API

    def _simulate_email(self, threat: Dict):

        print(f" ИМИТАЦИЯ: Отправка email администратору об угрозе {threat['type']}")
        # В реальном проекте здесь был бы код отправки через SMTP

    def get_blocking_summary(self) -> Dict:

        return {
            'total_blocked_ips': len(self.blocked_ips),
            'blocked_ips_list': list(self.blocked_ips),
            'total_responses': len(self.responses),
            'notifications_sent': self.notifications_sent
        }