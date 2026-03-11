import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from typing import Dict, Any, List
import os
import config


class ThreatReporter:
    """Класс для создания отчетов и графиков"""

    def __init__(self):
        self.report_path = config.REPORT_PATH
        self.graph_path = config.GRAPH_PATH
        self.csv_path = config.CSV_REPORT_PATH

        # Создаем директории если их нет
        os.makedirs(os.path.dirname(self.report_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.graph_path), exist_ok=True)

    def generate_report(self, collected_data: Dict, analysis: Dict,
                        responses: List[Dict], sources: List[str]) -> Dict:
        """
        Формирование полного отчета

        Args:
            collected_data: собранные данные
            analysis: результаты анализа
            responses: результаты реагирования
            sources: использованные источники

        Returns:
            Dict с полным отчетом
        """
        print("\n Формирование отчета...")

        report = {
            'report_id': f"THREAT-REPORT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'sources_used': sources,
            'summary': {
                'total_threats': analysis['statistics']['total_threats'],
                'critical_threats': analysis['statistics']['critical_threats'],
                'high_threats': analysis['statistics']['high_threats'],
                'responses_executed': len(responses),
                'blocked_ips': len(set().union(*[
                    r.get('blocking_details', {}).get('blocked_ip', '')
                    for r in responses if 'blocking_details' in r
                ])) if responses else 0
            },
            'threats_detailed': analysis['threats'],
            'responses_detailed': responses,
            'statistics': analysis['statistics']
        }

        # Сохраняем отчет в JSON
        self._save_json_report(report)

        # Сохраняем в CSV
        self._save_csv_report(analysis['threats'])

        print(f" Отчет сохранен в {self.report_path}")
        print(f" CSV данные сохранены в {self.csv_path}")

        return report

    def _save_json_report(self, report: Dict):
        """
        Сохранение отчета в JSON формате
        """
        try:
            with open(self.report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            print(f" Ошибка при сохранении JSON отчета: {e}")

    def _save_csv_report(self, threats: List[Dict]):
        """
        Сохранение данных угроз в CSV формате
        """
        try:
            if threats:
                df = pd.DataFrame(threats)
                # Преобразуем словари в строки для CSV
                for col in df.columns:
                    if df[col].apply(lambda x: isinstance(x, dict)).any():
                        df[col] = df[col].apply(json.dumps, default=str)
                df.to_csv(self.csv_path, index=False, encoding='utf-8')
        except Exception as e:
            print(f"❌ Ошибка при сохранении CSV отчета: {e}")

    def create_visualization(self, threats: List[Dict]) -> str:
        """
        Создание графика по результатам анализа

        Args:
            threats: список угроз

        Returns:
            str: путь к сохраненному графику
        """
        print("\n Создание визуализации...")

        if not threats:
            print(" Нет данных для визуализации")
            return None

        # Создаем DataFrame для удобства
        df = pd.DataFrame(threats)

        # Настройка стиля
        plt.style.use('seaborn-v0_8-darkgrid')
        sns.set_palette("husl")

        # Создаем фигуру с несколькими подграфиками
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Анализ угроз безопасности', fontsize=16, fontweight='bold')

        # График 1: Распределение по источникам
        if 'source' in df.columns:
            source_counts = df['source'].value_counts()
            axes[0, 0].bar(source_counts.index, source_counts.values)
            axes[0, 0].set_title('Распределение угроз по источникам')
            axes[0, 0].set_xlabel('Источник')
            axes[0, 0].set_ylabel('Количество')
            axes[0, 0].tick_params(axis='x', rotation=45)

        # График 2: Распределение по серьезности
        if 'severity' in df.columns:
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            severity_counts = df['severity'].value_counts().reindex(severity_order)
            colors = ['darkred', 'red', 'orange', 'yellow']
            axes[0, 1].bar(severity_counts.index, severity_counts.values, color=colors)
            axes[0, 1].set_title('Распределение угроз по уровню серьезности')
            axes[0, 1].set_xlabel('Уровень серьезности')
            axes[0, 1].set_ylabel('Количество')

        # График 3: Топ типов угроз
        if 'type' in df.columns:
            type_counts = df['type'].value_counts().head(5)
            axes[1, 0].barh(type_counts.index, type_counts.values)
            axes[1, 0].set_title('Топ-5 типов угроз')
            axes[1, 0].set_xlabel('Количество')

        # График 4: Круговая диаграмма (если есть CVSS баллы)
        if 'cvss_score' in str(df.columns):
            # Если есть данные CVSS, показываем их распределение
            if 'details' in df.columns:
                cvss_scores = []
                for details in df['details']:
                    if isinstance(details, dict) and 'cvss_score' in details:
                        cvss_scores.append(details['cvss_score'])
                if cvss_scores:
                    axes[1, 1].hist(cvss_scores, bins=10, edgecolor='black')
                    axes[1, 1].set_title('Распределение CVSS баллов')
                    axes[1, 1].set_xlabel('CVSS балл')
                    axes[1, 1].set_ylabel('Количество')
                else:
                    axes[1, 1].text(0.5, 0.5, 'Нет данных CVSS',
                                    ha='center', va='center', transform=axes[1, 1].transAxes)
                    axes[1, 1].set_title('Данные CVSS отсутствуют')
        else:
            # Показываем информацию о блокировках
            axes[1, 1].text(0.5, 0.5, 'Дополнительная статистика\nв JSON отчете',
                            ha='center', va='center', transform=axes[1, 1].transAxes)
            axes[1, 1].set_title('Статистика реагирования')

        plt.tight_layout()

        # Сохраняем график
        try:
            plt.savefig(self.graph_path, dpi=300, bbox_inches='tight')
            print(f" График сохранен в {self.graph_path}")
        except Exception as e:
            print(f" Ошибка при сохранении графика: {e}")

        plt.close()

        return self.graph_path

    def print_summary(self, report: Dict):

        print("\n" + "=" * 60)
        print(" СВОДКА ПО РЕЗУЛЬТАТАМ МОНИТОРИНГА")
        print("=" * 60)

        print(f"\nОтчет: {report['report_id']}")
        print(f"Прошло времени: {report['generated_at']}")
        print(f"Применение источники: {', '.join(report['sources_used'])}")

        print("\nСТАТИСТИКА УГРОЗ:")
        print(f"   Всего обнаружено угроз: {report['summary']['total_threats']}")
        print(f"   Критических: {report['summary']['critical_threats']}")
        print(f"   Высоких: {report['summary']['high_threats']}")

        print("\n РЕЗУЛЬТАТЫ РЕАГИРОВАНИЯ:")
        print(f"   Выполнено действий: {report['summary']['responses_executed']}")
        print(f"   Заблокировано IP: {report['summary']['blocked_ips']}")

        print("\n Сохраненные файлы:")
        print(f"   - JSON отчет: {self.report_path}")
        print(f"   - CSV данные: {self.csv_path}")
        print(f"   - График: {self.graph_path}")

        print("\n" + "=" * 60)