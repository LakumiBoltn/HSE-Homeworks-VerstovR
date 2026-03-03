"""
stages/reporting.py
-------------------
Этап 4 — Отчётность и визуализация.

Функции:
  - Сохранение объединённых результатов в CSV и JSON.
  - Построение столбчатой диаграммы из двух панелей (seaborn) в PNG.
"""

import json
import logging
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from config import REPORTS_DIR
from stages.response import BLOCKED_IPS

log = logging.getLogger(__name__)


def save_report(vt_df, suri_df):
    """Сохраняет объединённые результаты в CSV и JSON в папку reports/."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # CSV
    csv_path = REPORTS_DIR / f"report_{ts}.csv"
    frames = [f for f in (vt_df, suri_df) if not f.empty]
    if frames:
        pd.concat(frames, ignore_index=True).to_csv(csv_path, index=False)
        log.info("Отчёт сохранён -> %s", csv_path)

    # JSON
    json_path = REPORTS_DIR / f"report_{ts}.json"
    report = {
        "generated_at": ts,
        "virustotal": vt_df.fillna("N/A").to_dict(orient="records") if not vt_df.empty else [],
        "suricata":     suri_df.to_dict(orient="records") if not suri_df.empty else [],
        "blocked_ips":  sorted(BLOCKED_IPS),
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2, default=str)
    log.info("Отчёт сохранён -> %s", json_path)


def build_chart(vt_df, suri_df):
    """
    Строит столбчатую диаграмму из двух панелей и сохраняет в PNG.

    Левая  — оценки угроз VirusTotal (топ-6 целей).
    Правая — топ IP-адресов по количеству алертов Suricata.

    Выбор типа диаграммы (по блок-схеме):
      несколько похожих неупорядоченных значений без иерархии → столбчатая диаграмма.
    """
    sns.set_theme(style="whitegrid")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    chart_path = REPORTS_DIR / f"chart_{ts}.png"

    fig, (ax_vt, ax_su) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("Отчёт об обнаружении угроз", fontsize=14, fontweight="bold")

    # Левая панель — оценки VirusTotal
    if not vt_df.empty and "threat_score" in vt_df.columns:
        top = vt_df.nlargest(6, "threat_score").copy()
        top["Статус"] = top["is_threat"].map({True: "Угроза", False: "Безопасно"})
        sns.barplot(
            data=top, y="target", x="threat_score", hue="Статус",
            palette={"Угроза": "#d62728", "Безопасно": "#2ca02c"},
            dodge=False, ax=ax_vt,
        )
        ax_vt.set_xlabel("Оценка угрозы (malicious×2 + suspicious)")
        ax_vt.set_ylabel("")
    else:
        ax_vt.text(0.5, 0.5, "Нет данных VT", ha="center", va="center",
                   transform=ax_vt.transAxes)
    ax_vt.set_title("VirusTotal — Топ целей по оценке угрозы")

    # Правая панель — топ IP-адресов Suricata
    if not suri_df.empty and "src_ip" in suri_df.columns:
        ip_counts = (
            suri_df[suri_df["src_ip"] != "N/A"]["src_ip"]
            .value_counts()
            .head(6)
            .reset_index()
        )
        ip_counts.columns = ["src_ip", "count"]

        # Категория активности для легенды
        max_count = ip_counts["count"].max()
        ip_counts["Активность"] = ip_counts["count"].apply(
            lambda x: "Высокая" if x >= max_count * 0.66
            else ("Средняя" if x >= max_count * 0.33 else "Низкая")
        )
        sns.barplot(
            data=ip_counts, y="src_ip", x="count", hue="Активность",
            palette={"Высокая": "#d62728", "Средняя": "#ff7f0e", "Низкая": "#2ca02c"},
            dodge=False, ax=ax_su,
        )
        ax_su.set_xlabel("Количество событий-угроз")
        ax_su.set_ylabel("")
    else:
        ax_su.text(0.5, 0.5, "Нет данных Suricata", ha="center", va="center",
                   transform=ax_su.transAxes)
    ax_su.set_title("Suricata — Топ IP-адресов источников")

    plt.tight_layout()
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("Диаграмма сохранена -> %s", chart_path)
