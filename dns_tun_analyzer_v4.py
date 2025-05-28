from datetime import datetime
import json
import shutil
import numpy as np
import pyshark
import math
from collections import defaultdict, Counter
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from itertools import product
import os
import matplotlib.pyplot as plt
from scapy.all import rdpcap, DNSQR, DNS
import time


from os.path import isfile, join
from os import walk
from os import listdir
from INFO import *


class DNSTunnelDetector:
    
    idx = 0
    
    def __init__(self, advanced=False):
        # Метрики для каждого IP
        self.advanced=advanced
        self.metrics = {
            'avg_domain_len': ctrl.Antecedent(np.arange(0, 100, 1), 'avg_domain_len'),
            'subdomain_entropy': ctrl.Antecedent(np.arange(0, 6, 0.1), 'subdomain_entropy'),
            'query_frequency': ctrl.Antecedent(np.arange(0, 500, 10), 'query_frequency'),
            'unique_subdomains': ctrl.Antecedent(np.arange(0, 500, 10), 'unique_subdomains'),
            'digits': ctrl.Antecedent(np.arange(0, 10, 1), 'digits'),
            
        }
        
        # расширенный анализ
        if self.advanced:
            self.metrics['time_reg'] = ctrl.Antecedent(np.arange(0, 10, 0.1), 'time_reg')
            self.metrics['hex_coeff'] = ctrl.Antecedent(np.arange(0, 1.01, 0.01), 'hex_coeff')
            self.metrics['uniq_ratio'] = ctrl.Antecedent(np.arange(0, 1.01, 0.01), 'uniq_ratio')
            self.metrics['base64_ratio'] = ctrl.Antecedent(np.arange(0, 1.01, 0.01), 'base64_ratio')
            self.metrics['max_sub_len'] = ctrl.Antecedent(np.arange(0, 100, 1), 'max_sub_len')
            
        
        self.threat = ctrl.Consequent(np.arange(0, 101, 1), 'threat_level')

        self._setup_membership()
        self._setup_rules()

        self.control_system = ctrl.ControlSystem(self.rules)
        self.sim = ctrl.ControlSystemSimulation(self.control_system)
        # Данные для анализа
        self.ip_data = defaultdict(lambda: {
            'domains': [],
            'subdomains': [],
            'query_times': [],
            'domain_lengths': [],
            'digits': int(0)
        })
        self.whitelist = self._load_whitelist()
        
        

    def _load_whitelist(self):
        return {
            'google.com', 'youtube.com', 'facebook.com',
            'wikipedia.org', 'twitter.com', 'instagram.com',
            'apple.com', 'microsoft.com', 'cloudflare.com'
        }

    def _setup_membership(self):
        # Настройка функций принадлежности для каждой метрики
        self.metrics['avg_domain_len']['short'] = fuzz.trimf(self.metrics['avg_domain_len'].universe, [0, 15, 30])
        self.metrics['avg_domain_len']['medium'] = fuzz.trimf(self.metrics['avg_domain_len'].universe, [25, 45, 65])
        self.metrics['avg_domain_len']['long'] = fuzz.trapmf(self.metrics['avg_domain_len'].universe, [55, 70, 100, 100])

        self.metrics['subdomain_entropy']['low'] = fuzz.trimf(self.metrics['subdomain_entropy'].universe, [0, 1, 2.5])
        self.metrics['subdomain_entropy']['medium'] = fuzz.trimf(self.metrics['subdomain_entropy'].universe, [2, 3.2, 4.5])
        self.metrics['subdomain_entropy']['high'] = fuzz.trapmf(self.metrics['subdomain_entropy'].universe, [4, 4.8, 6, 6])

        self.metrics['query_frequency']['low'] = fuzz.trimf(self.metrics['query_frequency'].universe, [0, 50, 150])
        self.metrics['query_frequency']['medium'] = fuzz.trimf(self.metrics['query_frequency'].universe, [100, 250, 400])
        self.metrics['query_frequency']['high'] = fuzz.trapmf(self.metrics['query_frequency'].universe, [350, 450, 500, 500])

        self.metrics['unique_subdomains']['low'] = fuzz.trimf(self.metrics['unique_subdomains'].universe, [0, 50, 150])
        self.metrics['unique_subdomains']['medium'] = fuzz.trimf(self.metrics['unique_subdomains'].universe, [100, 250, 400])
        self.metrics['unique_subdomains']['high'] = fuzz.trapmf(self.metrics['unique_subdomains'].universe, [350, 450, 500, 500])
        
        self.metrics['digits']['low'] = fuzz.trimf(self.metrics['digits'].universe, [0, 1, 3])
        self.metrics['digits']['medium'] = fuzz.trimf(self.metrics['digits'].universe, [2, 4, 5])
        self.metrics['digits']['high'] = fuzz.trapmf(self.metrics['digits'].universe, [4, 6, 10, 10])
        
        self.threat['low'] = fuzz.trimf(self.threat.universe, [0, 10, 30])
        self.threat['medium'] = fuzz.trimf(self.threat.universe, [20, 50, 70])
        self.threat['high'] = fuzz.trapmf(self.threat.universe, [60, 80, 100, 100])
        
        # --- Для расширенного анализа --- #
        
        if self.advanced:
        
            self.metrics['time_reg']['low'] = fuzz.trimf(self.metrics['time_reg'].universe, [0, 0, 3])
            self.metrics['time_reg']['medium'] = fuzz.trimf(self.metrics['time_reg'].universe, [2, 5, 8])
            self.metrics['time_reg']['high'] = fuzz.trimf(self.metrics['time_reg'].universe, [7, 10, 10])

            # Hex Coefficient
            self.metrics['hex_coeff']['low'] = fuzz.trimf(self.metrics['hex_coeff'].universe, [0, 0, 0.3])
            self.metrics['hex_coeff']['medium'] = fuzz.trimf(self.metrics['hex_coeff'].universe, [0.2, 0.5, 0.8])
            self.metrics['hex_coeff']['high'] = fuzz.trimf(self.metrics['hex_coeff'].universe, [0.7, 1.0, 1.0])

            # Unique Char Ratio
            self.metrics['uniq_ratio']['low'] = fuzz.trimf(self.metrics['uniq_ratio'].universe, [0, 0, 0.4])
            self.metrics['uniq_ratio']['medium'] = fuzz.trimf(self.metrics['uniq_ratio'].universe, [0.3, 0.6, 0.8])
            self.metrics['uniq_ratio']['high'] = fuzz.trimf(self.metrics['uniq_ratio'].universe, [0.7, 1.0, 1.0])

            # Base64 Ratio
            self.metrics['base64_ratio']['low'] = fuzz.trimf(self.metrics['base64_ratio'].universe, [0, 0, 0.3])
            self.metrics['base64_ratio']['medium'] = fuzz.trimf(self.metrics['base64_ratio'].universe, [0.2, 0.5, 0.7])
            self.metrics['base64_ratio']['high'] = fuzz.trimf(self.metrics['base64_ratio'].universe, [0.6, 1.0, 1.0])

            # Max Subdomain Length
            self.metrics['max_sub_len']['short'] = fuzz.trimf(self.metrics['max_sub_len'].universe, [0, 0, 30])
            self.metrics['max_sub_len']['medium'] = fuzz.trimf(self.metrics['max_sub_len'].universe, [20, 50, 80])
            self.metrics['max_sub_len']['long'] = fuzz.trimf(self.metrics['max_sub_len'].universe, [70, 100, 100])


    def _setup_rules(self):
        domain_terms = ['short', 'medium', 'long']
        entropy_terms = ['low', 'medium', 'high']
        freq_terms = ['low', 'medium', 'high']
        unique_terms = ['low', 'medium', 'high']
        digits_terms = ['low', 'medium', 'high']

        # Весовые коэффициенты для каждой характеристики
        weights = {
            'domain_len': 0.9,    # Длина домена
            'entropy': 2.0,       # Энтропия поддоменов
            'frequency': 1.3,     # Частота запросов
            'unique': 1.5,        # Уникальные поддомены
            'digits': 2.0,
        }

        # Уровни важности (0-2)
        levels = {
            'short': 0, 'medium': 1, 'long': 2,
            'low': 0, 'medium': 1, 'high': 2
        }

        self.rules = []

        for d, e, f, u, g in product(domain_terms, entropy_terms, freq_terms, unique_terms, digits_terms):
            # Расчет комплексной оценки угрозы
            score = (
                weights['domain_len'] * levels[d] +
                weights['entropy'] * levels[e] +
                weights['frequency'] * levels[f] +
                weights['unique'] * levels[u] +
                weights['digits'] * levels[g]
            )

            # Определение уровня угрозы на основе оценки
            if score >= 7.5:
                threat_level = self.threat['high']
            elif score >= 4.5:
                threat_level = self.threat['medium']
            else:
                threat_level = self.threat['low']

            # Создание правила
            rule = ctrl.Rule(
                self.metrics['avg_domain_len'][d] &
                self.metrics['subdomain_entropy'][e] &
                self.metrics['query_frequency'][f] &
                self.metrics['unique_subdomains'][u] &
                self.metrics['digits'][g],
                threat_level
            )
            self.rules.append(rule)

        # Добавляем специальные правила для крайних случаев
        self.rules.extend([
            # Очень длинные домены с высокой энтропией - всегда опасны
            ctrl.Rule(
                self.metrics['avg_domain_len']['long'] & 
                self.metrics['subdomain_entropy']['high'] &
                self.metrics['digits']['high'],
                self.threat['high']
            ),
            
            # Много уникальных поддоменов с высокой частотой - всегда опасно
            ctrl.Rule(
                self.metrics['unique_subdomains']['high'] & 
                self.metrics['query_frequency']['high'],
                self.threat['high']
            ),
            
            # Низкие показатели по всем параметрам - безопасно
            ctrl.Rule(
                self.metrics['avg_domain_len']['short'] & 
                self.metrics['subdomain_entropy']['low'] & 
                self.metrics['query_frequency']['low'] & 
                self.metrics['unique_subdomains']['low'] &
                self.metrics['digits']['low'],
                self.threat['low']
            ),
        ])
        
        if self.advanced:
            self.rules.extend([
                ctrl.Rule(self.metrics['subdomain_entropy']['high'] & self.metrics['uniq_ratio']['high'], self.threat['high']),
                ctrl.Rule(self.metrics['query_frequency']['high'] & self.metrics['time_reg']['low'], self.threat['high']),
                ctrl.Rule(self.metrics['uniq_ratio']['high'] & self.metrics['hex_coeff']['high'], self.threat['high']),
                ctrl.Rule(self.metrics['max_sub_len']['long'] & self.metrics['uniq_ratio']['medium'], self.threat['medium']),
                ctrl.Rule(self.metrics['time_reg']['high'] & self.metrics['hex_coeff']['low'], self.threat['low']),
                ctrl.Rule(self.metrics['max_sub_len']['short'] & self.metrics['uniq_ratio']['low'], self.threat['low']),
                ctrl.Rule(self.metrics['base64_ratio']['low'] & self.metrics['uniq_ratio']['low'] & self.metrics['subdomain_entropy']['low'], self.threat['low']),
                ctrl.Rule(self.metrics['max_sub_len']['long'] & self.metrics['time_reg']['low'], self.threat['high']),
            ])

    def calculate_entropy(self, items):
        if not items:
            return 0
        counter = Counter(items)
        total = sum(counter.values())
        return -sum((count / total) * math.log2(count / total) for count in counter.values() if count > 0)

    def _is_whitelisted(self, domain):
        return any(domain.endswith(safe) for safe in self.whitelist)
    
 

    def lightweight_dns_tunnel_check(
        self,
        cap,
        length_threshold=50,
        uniq_ratio_threshold=0.9,
        freq_threshold=50,
        early_pkt_threshold=500
    ):

        domain_counts = defaultdict(int)
        subdomain_sets = defaultdict(set)
        timestamps = []
        pkt_counter = 0

        for pkt in cap:
            try:
                pkt_counter += 1
                if pkt_counter > early_pkt_threshold:
                    cap.close()
                    print('1')
                    return True  # слишком много DNS-пакетов — подозрение

                qname = pkt.dns.qry_name.rstrip('.')
                labels = qname.split('.')
                if len(labels) < 2:
                    continue

                domain = '.'.join(labels[-2:])  # example.com
                subdomain = '.'.join(labels[:-2]) if len(labels) > 2 else ''

                domain_counts[domain] += 1
                if subdomain:
                    subdomain_sets[domain].add(subdomain)

                if hasattr(pkt, 'sniff_time'):
                    timestamps.append(pkt.sniff_time.timestamp())

            except AttributeError:
                continue  # пропускаем пакеты без DNS-запроса

        cap.close()

        if not timestamps:
            print('2')
            return False  # Нет DNS-запросов

        suspicious_domains = 0
        for domain, subs in subdomain_sets.items():
            total = domain_counts[domain]
            uniq = len(subs)
            if total < 5:
                continue
            uniq_ratio = uniq / total
            avg_sub_len = sum(len(s) for s in subs) / uniq if uniq else 0

            if uniq_ratio > uniq_ratio_threshold and avg_sub_len > length_threshold:
                suspicious_domains += 1

        time_range = max(timestamps) - min(timestamps)
        freq = len(timestamps) / time_range if time_range > 0 else 0
        print(f'3 {suspicious_domains=} {freq=} {max(timestamps)=} {min(timestamps)=} {len(timestamps)=} {time_range=}')
        print(f'-----\n\n\n\n{timestamps}')
        return suspicious_domains > 0 or freq > freq_threshold

    def analyze_packet(self, pkt):
        try:
            if not hasattr(pkt.dns, 'qry_name'):
                return

            query = str(pkt.dns.qry_name).rstrip('.')
            if not query or self._is_whitelisted(query):
                return

            ip = pkt.ip.src
            dest = pkt.ip.dst
            data = self.ip_data[(ip, dest)]
            
            # Собираем данные для IP
            data['domains'].append(query)
            data['domain_lengths'].append(len(query))
            data['subdomains'].append(query.split('.')[0])
            data['query_times'].append(float(pkt.sniff_time.timestamp()))
            data['digits'] = max(data['digits'], sum(c.isdigit() for c in query))

        except Exception as e:
            print(f"Packet error: {e}")

    def evaluate_ip_threat(self, ip, dest, advanced_metrics=None):
        data = self.ip_data[(ip, dest)]
        if not data['domains']:
            return None

        print(f'----------\n{advanced_metrics=}')
        # Рассчитываем метрики для IP
        avg_len = np.mean(data['domain_lengths'])
        entropy = self.calculate_entropy(data['subdomains']) / avg_len 
        
        # Частота запросов (запросов в минуту)
        time_diff = max(data['query_times']) - min(data['query_times'])
        freq = len(data['query_times']) / (time_diff/60) if time_diff > 0 else 0
        
        unique_subs = len(set(data['subdomains']))
        digits = data['digits']

        # Нормализация
        if self.advanced:
            
            metrics = {
                'ip': ip,
                'avg_domain_len': min(avg_len, 100),
                'subdomain_entropy': min(entropy, 6),
                'query_frequency': min(freq, 500),
                'unique_subdomains': min(unique_subs, 500),
                'digits': min(digits, 10),
                'time_reg': advanced_metrics['time_reg'],
                'hex_coeff': advanced_metrics['hex_coeff'],
                'uniq_ratio': advanced_metrics['uniq_ratio'],
                'base64_ratio': advanced_metrics['base64_ratio'],
                'max_sub_len': advanced_metrics['max_sub_len'],
            }
        else:
            metrics = {
                'ip': ip,
                'avg_domain_len': min(avg_len, 100),
                'subdomain_entropy': min(entropy, 6),
                'query_frequency': min(freq, 500),
                'unique_subdomains': min(unique_subs, 500),
                'digits': min(digits, 10)
            }
        
        for name, value in metrics.items():
            if name == 'ip':
                continue
            self.sim.input[name] = value
            
        try:
            self.sim.compute()
            threat = self.sim.output['threat_level']
            
            # Дополнительные проверки
            if threat > 70 and avg_len < 60:
                threat *= 0.7
            
            metrics['threat'] = min(threat, 100)
            return metrics
        except:
            metrics['threat'] = 0.0
            return metrics

    def analyze_cap(self, capture):
        # Сбор данных
        for pkt in capture:
            self.analyze_packet(pkt)

        # Оценка для каждого IP
        results = []
        for ip, dest in self.ip_data:
            metrics = self.evaluate_ip_threat(ip, dest)
            if metrics == None:
                continue
            print(f'{metrics=}')
            if metrics['threat'] > 0:  # Игнорируем IP без DNS-запросов
                results.append(metrics)
        capture.close()
        print('-------------')
        print(results)
        
        return (DNS_TUN, NEED_REPORT, sorted(results, key=lambda x: x['threat'], reverse=True))
        # return dict(sorted(results.items(), key=lambda x: x[1], reverse=True))
        
    def save(self, info):
        self.sim.input['avg_domain_len'] = info['avg_domain_len']
        self.sim.input['subdomain_entropy'] = info['subdomain_entropy']
        self.sim.input['query_frequency'] = info['query_frequency']
        self.sim.input['unique_subdomains'] = info['unique_subdomains']
        self.sim.input['digits'] = info['digits']
        
        self.sim.compute()
        self.threat.view_user(sim=self.sim)
        plt.title('Результат распознавания потенциального\nDNS-туннелирования')
        plt.xlabel('Уровень потенциального DNS-туннелирования')
        plt.ylabel('Функция принадлежности')
        plt.legend(['Низкий', 'Средний', 'Высокий'], loc='upper left')
        
        path = f'/home/alex/Coding/FuzzySystem/reports/images/fuzzy_danger_level_dns_tun_{DNSTunnelDetector.idx}.png'
        
        plt.savefig(path, dpi=300, bbox_inches='tight')
        
        DNSTunnelDetector.idx += 1
        
        return path
    
    # ====------ ДЛЯ CRON ------==== #
    
    def _advanced_metrics(self, ip_data):
        """Расчет дополнительных метрик для углубленного анализа"""
        
        import re
        from scipy.stats import entropy as calc_entropy
        import numpy as np

        subdomains = ip_data['subdomains']
        query_times = ip_data['query_times']
        
        # 1. Коэффициент повторяемости поддоменов
        subdomain_counter = Counter(subdomains)
        repeat_coeff = sum(1 for cnt in subdomain_counter.values() if cnt > 1) / len(subdomain_counter) if subdomain_counter else 0
        
        # 2. Временная регулярность запросов
        time_diffs = np.diff(sorted(query_times))
        time_regularity = np.std(time_diffs) if len(time_diffs) > 1 else 0
        
        # # 3. Коэффициент использования HEX-символов
        # hex_chars = sum(1 for d in domains for c in d if c.lower() in 'abcdef')
        # hex_coeff = hex_chars / sum(len(d) for d in domains) if domains else 0
        
        #-----------
        all_labels = [label for d in subdomains for label in d.split('.') if label]

        # hex_coeff
        def is_hex(s): return re.fullmatch(r'[0-9a-fA-F]+', s) is not None
        hex_labels = [label for label in all_labels if is_hex(label)]
        hex_coeff = len(hex_labels) / len(all_labels) if all_labels else 0

        # unique_char_ratio
        all_chars = ''.join(all_labels)
        uniq_ratio = len(set(all_chars)) / len(all_chars) if all_chars else 0

        # base64_ratio
        def is_base64(s): return re.fullmatch(r'[A-Za-z0-9+/=]+', s) is not None
        base64_labels = [label for label in all_labels if is_base64(label)]
        base64_ratio = len(base64_labels) / len(all_labels) if all_labels else 0

        # max_sub_len
        max_sub_len = max(len(label) for label in all_labels) if all_labels else 0
        return {
            "repeat_coeff": repeat_coeff,
            "time_reg": time_regularity,
            "hex_coeff": hex_coeff,
            "uniq_ratio": uniq_ratio,
            "base64_ratio": base64_ratio,
            "max_sub_len": max_sub_len
        }
        
    def clear_data(self):
        self.ip_data.clear()

    def advanced_analysis(self, filepath):
        """
        Углубленный анализ специального файла с дополнительными метриками
        Args:
            filepath: Путь к pcap-файлу для анализа
        Returns:
            dict: Результаты анализа с расширенными метриками
        """
        # try:
        # Захват и базовый анализ трафика
        cap = pyshark.FileCapture(filepath, display_filter='dns && dns.flags.response==0 && ip')
        self.clear_data()
        # Чтобы проанализировать файл базовыми метриками
        # self.advanced=False
        # self.analyze_cap(cap)
        # self.advanced=True
        for pkt in cap:
            self.analyze_packet(pkt)
        cap.close()
        
        # Получение данных для всех IP
        results = []
        for (ip, dest), ip_data in self.ip_data.items():
            if not ip_data['domains']:
                continue
            
            # Дополнительные метрики
            adv_metrics = self._advanced_metrics(ip_data)
            print(f'---\n{adv_metrics=}')
            # Базовые метрики
            base_metrics = self.evaluate_ip_threat(ip, dest, adv_metrics)
            if not base_metrics:
                continue
            
            # Комплексная оценка
            combined_threat = base_metrics['threat'] * 0.7  # Базовые метрики 70%
            combined_threat += adv_metrics['repeat_coeff'] * 15  # Повторяемость 15%
            combined_threat += (1 - min(adv_metrics['time_reg'], 1)) * 10  # Регулярность 10%
            combined_threat += adv_metrics['hex_coeff'] * 5  # HEX-символы 5%
            
            result = {
                **base_metrics,
                **adv_metrics,
                'combined_threat': min(combined_threat, 100)
            }
            results.append(result)
        
        return {
            'filename': os.path.basename(filepath),
            'analysis_time': datetime.now().isoformat(),
            'results': sorted(results, key=lambda x: x['combined_threat'], reverse=True)
        }
            
        # except Exception as e:
        #     return {
        #         'error': str(e),
        #         'filename': os.path.basename(filepath),
        #         'analysis_time': datetime.now().isoformat()
        #     }

    @staticmethod
    def cron_analysis():
        """
        Метод для вызова из cron в заданное время
        Анализирует все файлы в специальной директории
        """
        SPECIAL_DIR = "/home/alex/Coding/FuzzySystem/pcaps/dns/TEST_CRON/"  # Укажите вашу директорию
        OUTPUT_FILE = "/home/alex/Coding/FuzzySystem/pcaps/dns/TEST_CRON/RES/dns_analysis_{date}.json"
        
        detector = DNSTunnelDetector(advanced=True)
        results = []
        
        for filename in os.listdir(SPECIAL_DIR):
            if filename.endswith('.pcap') or filename.endswith('.pcapng'):
                filepath = os.path.join(SPECIAL_DIR, filename)
                result = detector.advanced_analysis(filepath)
                results.append(result)
                
                # Архивируем обработанный файл
                processed_dir = os.path.join(SPECIAL_DIR, "processed")
                os.makedirs(processed_dir, exist_ok=True)
                # shutil.move(filepath, os.path.join(processed_dir, filename))
        
        # Сохраняем результаты
        output_path = OUTPUT_FILE.format(date=datetime.now().strftime("%Y%m%d_%H%M"))
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
            
        return output_path

# Пример использования
if __name__ == "__main__":
    # detector = DNSTunnelDetector()
    
    # Опасный pcap
    # cap = pyshark.FileCapture('/home/alex/Coding/FuzzySystem/pcaps/dns-tunnel-iodine.pcap', display_filter='dns && dns.flags.response==0 && ip')
    # Безопасный pcap
    cap = pyshark.FileCapture('/home/alex/Coding/FuzzySystem/pcaps/dns/benign_tun_01.pcap', display_filter='dns')
    
    # cap = pyshark.FileCapture('/home/alex/Coding/FuzzySystem/pcaps/dns_tunn.pcapng', display_filter='dns && dns.flags.response==0')
    # print(detector.analyze_cap(cap))
    ATTACK_DIR = "/home/alex/Coding/FuzzySystem/pcaps/dns/tunnel"
    NORMAL_DIR = "/home/alex/Coding/FuzzySystem/pcaps/dns/normal"
    
    CUR_DIR = ATTACK_DIR
    
    onlyfiles = [f for f in listdir(CUR_DIR)]
    
    # # print(onlyfiles)
    
    for file in onlyfiles:
        detector = DNSTunnelDetector()
        print(file)
        cap = pyshark.FileCapture(join(CUR_DIR, file), display_filter='dns && dns.flags.response==0 && ip')
        res = detector.analyze_cap(cap)[2]
        print(f'Оценка: {res}')
        for m in res:
            print(m)
            if m['threat'] > 70:
                print("Обнаружена потенциальная DNS-туннелизация!")
            elif m['threat'] > 40:
                print("Подозрительная активность")
            else:
                print("Трафик выглядит нормально")
            print('\n\n\n')
            
            
    