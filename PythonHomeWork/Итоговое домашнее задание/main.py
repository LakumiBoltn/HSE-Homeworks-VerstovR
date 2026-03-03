"""
Автоматизированное обнаружение и реагирование на угрозы
=======================================================
Оркестратор — последовательно запускает четыре этапа конвейера.

  Этап 1  stages/collection.py  — сбор данных: VirusTotal API + парсинг логов Suricata
  Этап 2  stages/analysis.py    — анализ угроз на основе pandas
  Этап 3  stages/response.py    — имитация блокировки IP + уведомления
  Этап 4  stages/reporting.py   — CSV/JSON-отчёт + диаграмма (PNG)

Все константы и переменные окружения хранятся в config.py.
"""

import logging
from datetime import datetime

from config import LOGS_DIR
from stages.collection import collect_virustotal_data, parse_suricata_logs
from stages.analysis import analyse_virustotal, analyse_suricata
from stages.response import respond_to_vt_threats, respond_to_suricata_threats, BLOCKED_IPS
from stages.reporting import save_report, build_chart

log = logging.getLogger(__name__)


def main():
    print("=" * 60)
    print("  Автоматизированное обнаружение и реагирование на угрозы")
    print(f"  Время запуска: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Этап 1: Сбор данных
    # ------------------------------------------------------------------
    print("\n[Этап 1] Сбор данных ...")

    log.info("Запуск проверок VirusTotal ...")
    vt_raw = collect_virustotal_data()

    log.info("Парсинг логов Suricata ...")
    suricata_df = parse_suricata_logs(LOGS_DIR / "eve.json")

    # ------------------------------------------------------------------
    # Этап 2: Анализ
    # ------------------------------------------------------------------
    print("\n[Этап 2] Анализ угроз ...")

    vt_analysed = analyse_virustotal(vt_raw)
    suri_threats = analyse_suricata(suricata_df)

    threats_found = (
        (not vt_analysed.empty and vt_analysed["is_threat"].any())
        or not suri_threats.empty
    )

    print(f"\n  Проверено целей VirusTotal : {len(vt_analysed)}")
    if not vt_analysed.empty:
        cols = [c for c in ("target", "type", "malicious", "suspicious",
                            "threat_score", "is_threat") if c in vt_analysed.columns]
        print(vt_analysed[cols].to_string(index=False))

    print(f"\n  Событий-угроз Suricata     : {len(suri_threats)}")
    if not suri_threats.empty:
        cols = [c for c in ("src_ip", "type", "description", "severity")
                if c in suri_threats.columns]
        print(suri_threats[cols].to_string(index=False))

    # ------------------------------------------------------------------
    # Этап 3: Реагирование
    # ------------------------------------------------------------------
    print("\n[Этап 3] Реагирование на угрозы ...")
    if threats_found:
        respond_to_vt_threats(vt_analysed)
        respond_to_suricata_threats(suri_threats)
        print(f"\n  Заблокировано IP ({len(BLOCKED_IPS)}): "
              f"{', '.join(sorted(BLOCKED_IPS)) or '-'}")
    else:
        print("  Угроз не обнаружено. Действий не требуется.")

    # ------------------------------------------------------------------
    # Этап 4: Отчёт
    # ------------------------------------------------------------------
    print("\n[Этап 4] Сохранение отчёта и диаграммы ...")
    save_report(vt_analysed, suri_threats)
    build_chart(vt_analysed, suri_threats)

    print("\n" + "=" * 60)
    print("  Готово. Результаты в папке 'reports/'.")
    print("=" * 60)


if __name__ == "__main__":
    main()
