import numpy as np
import pyshark
import math
from collections import defaultdict, Counter
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from itertools import product
import os
import numpy as np
import matplotlib.pyplot as plt
import pyshark
import math
from collections import defaultdict, Counter
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from itertools import product
from os.path import isfile, join
from os import walk
from os import listdir
from INFO import *

class DNSTunnelDetector:
    
    idx = 0
    
    def __init__(self):
        # Метрики для каждого IP
        self.metrics = {
            'avg_domain_len': ctrl.Antecedent(np.arange(0, 100, 1), 'avg_domain_len'),
            'subdomain_entropy': ctrl.Antecedent(np.arange(0, 6, 0.1), 'subdomain_entropy'),
            'query_frequency': ctrl.Antecedent(np.arange(0, 500, 10), 'query_frequency'),
            'unique_subdomains': ctrl.Antecedent(np.arange(0, 500, 10), 'unique_subdomains'),
            'digits': ctrl.Antecedent(np.arange(0, 10, 1), 'digits'),
        }
        
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
            )
        ])

    def calculate_entropy(self, items):
        if not items:
            return 0
        counter = Counter(items)
        total = sum(counter.values())
        return -sum((count / total) * math.log2(count / total) for count in counter.values() if count > 0)

    def _is_whitelisted(self, domain):
        return any(domain.endswith(safe) for safe in self.whitelist)

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

    def evaluate_ip_threat(self, ip, dest):
        data = self.ip_data[(ip, dest)]
        if not data['domains']:
            return None

        # Рассчитываем метрики для IP
        avg_len = np.mean(data['domain_lengths'])
        entropy = self.calculate_entropy(data['subdomains']) / avg_len 
        
        # Частота запросов (запросов в минуту)
        time_diff = max(data['query_times']) - min(data['query_times'])
        freq = len(data['query_times']) / (time_diff/60) if time_diff > 0 else 0
        
        unique_subs = len(set(data['subdomains']))
        digits = data['digits']

        # Нормализация
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

            if metrics['threat'] > 0:  # Игнорируем IP без DNS-запросов
                results.append(metrics)
        capture.close()
        
        
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

# Пример использования
if __name__ == "__main__":
    # detector = DNSTunnelDetector()
    
    # Опасный pcap
    # cap = pyshark.FileCapture('/home/alex/Coding/FuzzySystem/pcaps/dns-tunnel-iodine.pcap', display_filter='dns && dns.flags.response==0 && ip')
    # Безопасный pcap
    # cap = pyshark.FileCapture('/home/alex/Coding/FuzzySystem/pcaps/dns/benign_tun_01.pcap', display_filter='dns')
    
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
            
            
    