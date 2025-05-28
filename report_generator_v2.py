import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from jinja2 import Template
from INFO import *

class ReportGenerator():
    
    idx = 0
    
    @staticmethod
    def load_metrics_from_json(json_path):
        with open(json_path, 'r', encoding='utf-8') as f:
            metrics_list = json.load(f)
        return metrics_list
    
    @staticmethod
    def gen_dns_tun(metrics, filename="none", path=None):
        """
        Генерирует HTML-отчет по результатам обнаружения DNS-туннелирования
        """
        
        title_text = "Отчет об обнаружении DNS-туннелирования"
        
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
        for metrics in metrics:
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
                threat_class = "high-threat"
            elif threat > 40:
                status = "Подозрительная"
                recommendation = "Мониторинг и анализ"
                threat_class = "medium-threat"
            else:
                status = "Нормальная"
                recommendation = "Действия не требуются"
                threat_class = "normal"
                
            data["Статус"].append(status)
            data["Рекомендации"].append(recommendation)
        
        df = pd.DataFrame(data)

        # HTML-шаблон отчета
        html_template = """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ title_text }}</title>
            <style>
                :root {
                    --primary: #3498db;
                    --danger: #e74c3c;
                    --warning: #f39c12;
                    --success: #2ecc71;
                    --dark: #2c3e50;
                    --light: #ecf0f1;
                }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 20px;
                    background-color: #f9f9f9;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.1);
                    border-radius: 8px;
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 1px solid #eee;
                }
                .header h1 {
                    color: var(--dark);
                    margin: 0;
                    font-size: 28px;
                }
                .header .subtitle {
                    color: #7f8c8d;
                    font-size: 14px;
                }
                .report-section {
                    margin-bottom: 30px;
                }
                .section-title {
                    color: var(--primary);
                    border-bottom: 2px solid var(--primary);
                    padding-bottom: 5px;
                    margin-top: 30px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                    font-size: 14px;
                }
                th {
                    background-color: var(--dark);
                    color: white;
                    text-align: left;
                    padding: 12px;
                }
                td {
                    padding: 10px 12px;
                    border-bottom: 1px solid #ddd;
                }
                tr:hover {
                    background-color: #f5f5f5;
                }
                .high-threat {
                    background-color: rgba(231, 76, 60, 0.1);
                    border-left: 3px solid var(--danger);
                }
                .medium-threat {
                    background-color: rgba(243, 156, 18, 0.1);
                    border-left: 3px solid var(--warning);
                }
                .normal {
                    background-color: rgba(46, 204, 113, 0.1);
                    border-left: 3px solid var(--success);
                }
                .badge {
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: bold;
                }
                .badge-danger {
                    background-color: var(--danger);
                    color: white;
                }
                .badge-warning {
                    background-color: var(--warning);
                    color: white;
                }
                .badge-success {
                    background-color: var(--success);
                    color: white;
                }
                .chart-container {
                    text-align: center;
                    margin: 30px 0;
                    padding: 20px;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 0 15px rgba(0,0,0,0.05);
                }
                .chart-container img {
                    max-width: 100%;
                    height: auto;
                    border-radius: 4px;
                }
                .metrics-info {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 20px;
                    margin: 20px 0;
                }
                .metric-card {
                    flex: 1;
                    min-width: 200px;
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.05);
                    border-top: 3px solid var(--primary);
                }
                .metric-card h4 {
                    margin-top: 0;
                    color: var(--dark);
                }
                .footer {
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                    color: #7f8c8d;
                    font-size: 12px;
                }
                .threat-scale {
                    display: flex;
                    margin: 20px 0;
                }
                .threat-level {
                    flex: 1;
                    padding: 10px;
                    text-align: center;
                    color: white;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{{ title_text }}</h1>
                    <div class="subtitle">Сгенерировано: {{ date }}</div>
                    <div class="subtitle">Файл: {{ filename }}</div>
                </div>
                
                <div class="report-section">
                    <h2 class="section-title">Результаты анализа</h2>
                    
                    <div class="threat-scale">
                        <div class="threat-level" style="background-color: #2ecc71;">Низкий риск (0-40)</div>
                        <div class="threat-level" style="background-color: #f39c12;">Средний риск (40-70)</div>
                        <div class="threat-level" style="background-color: #e74c3c;">Высокий риск (70-100)</div>
                    </div>
                    
                    {{ table|safe }}
                </div>
                
                {% if path %}
                <div class="report-section">
                    <h2 class="section-title">Визуализация данных</h2>
                    <div class="chart-container">
                        <img src="{{ path }}" alt="График активности DNS">
                    </div>
                </div>
                {% endif %}
                
                <div class="report-section">
                    <h2 class="section-title">Анализируемые метрики</h2>
                    <div class="metrics-info">
                        <div class="metric-card">
                            <h4>Средняя длина домена</h4>
                            <p>Длинные домены (>50 символов) часто используются в туннелировании для передачи данных</p>
                        </div>
                        <div class="metric-card">
                            <h4>Энтропия поддоменов</h4>
                            <p>Высокие значения (>3.5) могут указывать на зашифрованные или сжатые данные в поддоменах</p>
                        </div>
                        <div class="metric-card">
                            <h4>Частота запросов</h4>
                            <p>Аномально высокая частота (>300/мин) характерна для туннелей передачи данных</p>
                        </div>
                        <div class="metric-card">
                            <h4>Уникальные поддомены</h4>
                            <p>Большое количество (>200) уникальных поддоменов - признак туннеля</p>
                        </div>
                        <div class="metric-card">
                            <h4>Цифры в домене</h4>
                            <p>Много цифр (>4) может указывать на передачу двоичных данных в текстовом виде</p>
                        </div>
                    </div>
                </div>
                
                <div class="report-section">
                    <h2 class="section-title">Рекомендации</h2>
                    <ul>
                        <li><strong>Для высокорисковых IP:</strong> Немедленная блокировка, изоляция от сети, детальный анализ трафика</li>
                        <li><strong>Для подозрительных IP:</strong> Мониторинг активности, сбор дополнительных логов, проверка на других системах</li>
                        <li><strong>Для всех случаев:</strong> Проверка DNS-серверов на предмет необычных записей, анализ конфигураций</li>
                    </ul>
                </div>
                
                <div class="footer">
                    Отчет сгенерирован автоматически системой мониторинга безопасности<br>
                    Версия 1.0 | {{ date }}
                </div>
            </div>
        </body>
        </html>
        """

        # Функция для стилизации строк таблицы
        def style_threat_level(row):
            threat = float(row['Уровень угрозы'])
            if threat > 70:
                return ['background-color: rgba(231, 76, 60, 0.05)'] * len(row)
            elif threat > 40:
                return ['background-color: rgba(243, 156, 18, 0.05)'] * len(row)
            return [''] * len(row)
        
        # Применяем стили к таблице
        styled_df = df.style.apply(style_threat_level, axis=1)\
                          .format({'Уровень угрозы': lambda x: f"<span class='badge badge-{'danger' if float(x)>70 else 'warning' if float(x)>40 else 'success'}'>{x}</span>"})\
                          .format({'Статус': lambda x: f"<span class='badge badge-{'danger' if 'Высокая' in x else 'warning' if 'Подозрительная' in x else 'success'}'>{x}</span>"})

        # Рендеринг HTML
        template = Template(html_template)
        html_report = template.render(
            title_text=title_text,
            filename=filename,
            path=path if path else None,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            table=styled_df.to_html(index=False, escape=False, classes="styled-table")
        )

        # Сохранение отчета
        path_report = f"/home/alex/Coding/FuzzySystem/reports/dns_tunnel_report_{ReportGenerator.idx}.html"
        with open(path_report, "w", encoding="utf-8") as f:
            f.write(html_report)
        
        ReportGenerator.idx += 1

        print(f"Отчет сохранен: {path_report}")
        return path_report

    @staticmethod
    def generate_report(tag, json_path, image_path=None):
        """
        Генератор отчетов с единой точкой входа
        
        :param tag: Тип отчета (DNS_TUN, ARP_SPOOF, PORT_SCAN)
        :param json_path: Путь к JSON-файлу с результатами анализа
        :param image_path: Путь к изображению с графиком
        :return: Путь к сохраненному отчету
        """
        json_data = ReportGenerator.load_metrics_from_json(json_path)

        for file_metrics in json_data:
            print(f'{file_metrics['filename']}')
            if tag == DNS_TUN:
                ReportGenerator.gen_dns_tun(file_metrics['results'], file_metrics['filename'], image_path)
            elif tag == PORT_SCAN:
                pass  # future extension
            elif tag == ARP_SPOOF:
                pass  # future extension
            else:
                raise ValueError(f"Unknown report tag: {tag}")