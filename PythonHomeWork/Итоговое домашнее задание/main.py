#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
from datetime import datetime
from data_collector import DataCollector
from threat_analyzer import ThreatAnalyzer
from responder import ThreatResponder
from reporter import ThreatReporter


def print_banner():

    banner = """
███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗    
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    
███████╗███████╗██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝    
╚════██║██╔════╝██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝      
███████║███████║╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║      
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝      

███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗ 
████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗██║████╗  ██║██╔════╝ 
██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝██║██╔██╗ ██║██║  ███╗
██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗██║██║╚██╗██║██║   ██║
██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║██║██║ ╚████║╚██████╔╝
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 

███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗
██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║
███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║
╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║
███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║
╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
    """
    print(banner)


def main():

    
    print_banner()
    start_time = time.time()
    
    try:
        # Этап 1: Инициализация компонентов
        print("\nИнициализация системы мониторинга...")
        collector = DataCollector()
        analyzer = ThreatAnalyzer()
        responder = ThreatResponder()
        reporter = ThreatReporter()
        
        # Этап 2: Сбор данных
        print("\n" + "="*60)
        print("ЭТАП 1: СБОР ДАННЫХ ИЗ ИСТОЧНИКОВ")
        print("="*60)
        
        collected_data = collector.collect_from_all_sources()
        sources_used = collector.get_sources_used()
        
        print(f"\n Сбор данных завершен. Использовано источников: {len(sources_used)}")
        print(f" Источники: {', '.join(sources_used)}")
        
        # Этап 3: Анализ данных
        print("\n" + "="*60)
        print("ЭТАП 2: АНАЛИЗ ДАННЫХ И ВЫЯВЛЕНИЕ УГРОЗ")
        print("="*60)
        
        analysis = analyzer.analyze_all_data(collected_data)
        
        # Этап 4: Реагирование на угрозы
        print("\n" + "="*60)
        print("ЭТАП 3: РЕАГИРОВАНИЕ НА УГРОЗЫ")
        print("="*60)
        
        responses = responder.respond_to_threats(analysis['threats'])
        
        # Этап 5: Формирование отчета и визуализация
        print("\n" + "="*60)
        print("ЭТАП 4: ФОРМИРОВАНИЕ ОТЧЕТА И ВИЗУАЛИЗАЦИЯ")
        print("="*60)
        
        report = reporter.generate_report(collected_data, analysis, responses, sources_used)
        reporter.create_visualization(analysis['threats'])
        
        # Вывод итоговой сводки
        reporter.print_summary(report)
        
        # Время выполнения
        execution_time = time.time() - start_time
        print(f"\n Общее время выполнения: {execution_time:.2f} секунд")
        
        # Проверка использования двух источников
        if len(sources_used) >= 2:
            print(" УСЛОВИЕ ВЫПОЛНЕНО: Использовано минимум 2 источника данных")
        else:
            print(" ВНИМАНИЕ: Использовано менее 2 источников данных")
        
        print("\n Работа успешно завершена!")
        
    except KeyboardInterrupt:
        print("\n\n Программа прервана пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"\n Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()