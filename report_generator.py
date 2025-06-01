import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from jinja2 import Template
from CONFIG_INFO import *

class ReportGenerator():
    
    idx = 0
    
    @staticmethod
    def gen_dns_tun(info, path=None):
        """
        Генерирует HTML-отчет по результатам обнаружения DNS-туннелирования
        
        :param info: Кортеж с результатами анализа (DNS_TUN, NEED_REPORT, metrics_list)
        :param path: Путь к изображению с графиком (опционально)
        :return: Путь к сохраненному отчету
        """
        # Извлекаем список метрик из кортежа
        metrics_list = info
        
        title_text = "Результаты проверки на DNS-туннелирование"
        
        # Подготовка данных для таблицы
        data = {
            "IP адрес": [],
            "Уровень угрозы": [],
            "Ср. длина домена": [],
            "Энтропия поддоменов": [],
            "Частота запросов": [],
            "Уник. поддомены": [],
            "Цифры в домене": [],
            "Статус": [],
            "Рекомендации": []
        }
        
        for metrics in metrics_list:
            threat = metrics['threat']
            
            data["IP адрес"].append(metrics['ip'])
            data["Уровень угрозы"].append(f"{round(threat, 2)}")
            data["Ср. длина домена"].append(f"{round(metrics['avg_domain_len'], 2)}")
            data["Энтропия поддоменов"].append(f"{round(metrics['subdomain_entropy'], 2)}")
            data["Частота запросов"].append(f"{round(metrics['query_frequency'], 2)}")
            data["Уник. поддомены"].append(f"{metrics['unique_subdomains']}")
            data["Цифры в домене"].append(f"{metrics['digits']}")
            
            if threat > 70:
                status = "Высокая угроза"
                recommendation = "Блокировка и расследование"
            elif threat > 40:
                status = "Подозрительная"
                recommendation = "Мониторинг и анализ"
            else:
                status = "Нормальная"
                recommendation = "Действия не требуются"
                
            data["Статус"].append(status)
            data["Рекомендации"].append(recommendation)
        
        df = pd.DataFrame(data)

        # HTML-шаблон отчета
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ title_text }}</title>
            <style>
                body { font-family: Arial; margin: 20px; }
                h1 { color: #2c3e50; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                img { max-width: 800px; margin-top: 20px; }
                .high-threat { background-color: #ffdddd; }
                .medium-threat { background-color: #fff3cd; }
                .normal { background-color: #d4edda; }
            </style>
        </head>
        <body>
            <h1>{{ title_text }}</h1>
            <p>Сгенерировано: {{ date }}</p>
            
            <h2>Детализированные результаты анализа</h2>
            {{ table|safe }}
            
            {% if path %}
            <h2>График активности</h2>
            <img src={{ path }}>
            {% endif %}
            
            <h2>Интерпретация уровней угрозы</h2>
            <table style="width: 100%; margin-bottom: 20px;">
                <tr>
                    <th style="background-color: #ffdddd;">Высокая (>70)</th>
                    <td>Явные признаки DNS-туннелирования. Рекомендуется немедленное реагирование.</td>
                </tr>
                <tr>
                    <th style="background-color: #fff3cd;">Подозрительная (40-70)</th>
                    <td>Возможные признаки аномальной активности. Требуется дополнительный анализ.</td>
                </tr>
                <tr>
                    <th style="background-color: #d4edda;">Нормальная (<40)</th>
                    <td>Активность не вызывает подозрений.</td>
                </tr>
            </table>
            
            <h2>Анализируемые метрики</h2>
            <ul>
                <li><strong>Средняя длина домена:</strong> Длинные домены (обычно >50 символов) чаще используются в туннелировании</li>
                <li><strong>Энтропия поддоменов:</strong> Высокие значения (>3.5) могут указывать на зашифрованные данные</li>
                <li><strong>Частота запросов:</strong> Аномально высокая частота (>300/мин) характерна для туннелей</li>
                <li><strong>Уникальные поддомены:</strong> Большое количество (>200) уникальных поддоменов - признак туннеля</li>
                <li><strong>Цифры в домене:</strong> Много цифр (>4) может указывать на передачу двоичных данных</li>
            </ul>
        </body>
        </html>
        """

        # Функция для стилизации строк таблицы
        def style_threat_level(row):
            threat = float(row['Уровень угрозы'])
            style = []
            for val in row:
                if threat > 70:
                    style.append('background-color: #ffdddd')
                elif threat > 40:
                    style.append('background-color: #fff3cd')
                else:
                    style.append('background-color: #d4edda')
            return style
        
        # Применяем стили к таблице
        styled_df = df.style.apply(style_threat_level, axis=1)

        # Рендеринг HTML
        template = Template(html_template)
        html_report = template.render(
            title_text=title_text,
            path=path if path else None,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            table=styled_df.to_html(index=False, escape=False)
        )

        # Сохранение отчета
        path_report = f"{REPORT_DIR}dns_tunnel_report_{ReportGenerator.idx}.html"
        with open(path_report, "w", encoding="utf-8") as f:
            f.write(html_report)
        
        ReportGenerator.idx += 1

        print(f"Отчет сохранен: {path_report}")
        return path_report
    
    @staticmethod
    def gen_spoof(info, path):
        title_text = "Результат проверки на ARP-spoofing"
        
        # 1. Создаем DataFrame с данными
        data = {
            "MAC адрес": [f"{row['mac']}" for row in info],
            "Уровень угрозы (0-100)": [f"{round(row['threat'], 2)}" for row in info],
            "Количество конфликтов IP": [f"{row['ip_conflicts']}" for row in info],
            "Количество изменений MAC": [f"{row['mac_changes']}" for row in info],
            "Заявленные IP адреса": [", ".join(row['claimed_ips']) for row in info],
            "ARP запросов": [f"{row['stats']['requests']}" for row in info],
            "ARP ответов": [f"{row['stats']['responses']}" for row in info],
            "Незапрошенных ответов": [f"{row['stats']['unsolicited']}" for row in info],
        }
        
        df = pd.DataFrame(data)

        # 2. Создаем HTML-шаблон
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ title_text }}</title>
            <style>
                body { font-family: Arial; margin: 20px; }
                h1 { color: #2c3e50; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                img { max-width: 800px; margin-top: 20px; }
                .warning { color: #e67e22; font-weight: bold; }
                .danger { color: #e74c3c; font-weight: bold; }
            </style>
        </head>
        <body>
            <h1>{{ title_text }}</h1>
            <p>Сгенерировано: {{ date }}</p>
            
            <h2>Обнаруженные потенциальные ARP-spoofing атаки</h2>
            {{ table|safe }}
            
            {% if path %}
            <h2>График активности</h2>
            <img src={{ path }}>
            {% endif %}
            
            <h2>Интерпретация результатов</h2>
            <ul>
                <li><span class="danger">Высокий уровень угрозы</span> (70-100) - вероятно ARP-spoofing атака</li>
                <li><span class="warning">Средний уровень угрозы</span> (30-70) - подозрительная активность</li>
                <li>Низкий уровень угрозы (0-30) - нормальная сетевая активность</li>
            </ul>
            
            <h2>Анализируемые параметры</h2>
            <ul>
                <li><strong>Конфликты IP</strong> - сколько разных IP заявляет один MAC</li>
                <li><strong>Изменения MAC</strong> - как часто менялся MAC для IP</li>
                <li><strong>Незапрошенные ответы</strong> - ARP ответы без предшествующего запроса</li>
            </ul>
        </body>
        </html>
        """

        # 3. Рендерим HTML с данными
        template = Template(html_template)
        html_report = template.render(
            title_text=title_text,
            path=path if path else None,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            table=df.to_html(index=False, escape=False)
        )

        # 4. Сохраняем отчет
        path_report = f"{REPORT_DIR}arp_spoof_report_{ReportGenerator.idx}.html"
        with open(path_report, "w", encoding="utf-8") as f:
            f.write(html_report)
        
        ReportGenerator.idx += 1

        print(f"Отчет сохранен: {path_report}")
        return path_report
        
        
    @staticmethod
    def gen_port_scan(info, path):
        title_text = "Результат проверки на сканирование портов"
        # 1. Создаем тестовые данные
        data = {
            "IP потенциального сканера": [f"{row[1]}" for row in info],
            "Количество отправленных пакетов": [f"{row[2]}" for row in info],
            "Время активности в секундах": [f"{row[2]//row[4]}" for row in info],
            "Количество уникальных запрошенных портов": [f"{row[3]}" for row in info],
            "Количество отправленных пакетов в секунду": [f"{row[4]}" for row in info],
            "Уровень потенциального сканирования, 0-100": [f"{round(row[0], 5)}" for row in info],
        }
        df = pd.DataFrame(data)

        # 3. Создаем HTML-шаблон
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ title_text }}</title>
            <style>
                body { font-family: Arial; margin: 20px; }
                h1 { color: #2c3e50; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                img { max-width: 800px; margin-top: 20px; }
            </style>
        </head>
        <body>
            <h1>{{ title_text }}</h1>
            <p>Сгенерировано: {{ date }}</p>
            
            <h2>Данные</h2>
            {{ table|safe }}
            
            <h2>График</h2>
            <img src={{ path }}>
        </body>
        </html>
        """

        # 4. Рендерим HTML с данными
        template = Template(html_template)
        html_report = template.render(
            title_text=title_text,  # Добавлено
            path=path,             # Добавлено
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            table=df.to_html(index=False)
        )

        # 5. Сохраняем отчет
        path_report = f"{REPORT_DIR}port_scan_report_{ReportGenerator.idx}.html"
        with open(path_report, "w", encoding="utf-8") as f:
            f.write(html_report)
        
        ReportGenerator.idx += 1

        print(f"Отчет сохранен: {path_report}")
    
    @staticmethod
    def generate_report(tag, info, path):
        
        if tag == PORT_SCAN:
            info = [info] # TODO реализовать получение списка аномальных записей
            ReportGenerator.gen_port_scan(info, path)
        
        if tag == ARP_SPOOF:
            ReportGenerator.gen_spoof(info, path)
        
        if tag == DNS_TUN:
            ReportGenerator.gen_dns_tun(info, path)