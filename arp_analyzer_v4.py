import numpy as np
import matplotlib.pyplot as plt
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from collections import defaultdict
import pyshark
from scapy.all import ARP, sniff
import time
from itertools import product
from INFO import *

DEBUG = True
MAX_ARP_RESPONSES = 50
MAX_MAC_CHANGES = 5
MAX_IP_CLAIMS = 3  # Максимальное количество разных IP, заявленных одним MAC
UNSOLICITED_THRESHOLD = 2.0  # 2 секунды для определения неожиданных ответов
WHITELIST_IPS = {}  # {'192.168.1.1', '192.168.1.2'}

class ARPSpoofingDetector:
    
    idx = 0
    
    def __init__(self):
        # Лингвистические переменные
        self.arp_responses = ctrl.Antecedent(np.arange(0, MAX_ARP_RESPONSES+1, 1), 'arp_responses')
        self.mac_changes = ctrl.Antecedent(np.arange(0, MAX_MAC_CHANGES+1, 1), 'mac_changes')
        self.unsolicited_score = ctrl.Antecedent(np.arange(0, 101, 1), 'unsolicited_score')
        self.ip_conflicts = ctrl.Antecedent(np.arange(0, MAX_IP_CLAIMS+1, 1), 'ip_conflicts')
        
        self.threat_level = ctrl.Consequent(np.arange(0, 101, 1), 'threat_level')

        self._setup_membership()
        self._setup_rules()
        
        self.control_system = ctrl.ControlSystem(self.rules)
        self.simulation = ctrl.ControlSystemSimulation(self.control_system)
        
        # self.threat_level.view_user()
        # plt.ylabel('Величина принадлежности')
        # plt.xlabel('Уровень угрозы')
        # plt.title('Ф. п. для терма "уровень угрозы"')
        # plt.show()

    def _setup_membership(self):
        # ARP Responses
        self.arp_responses['low'] = fuzz.trimf(self.arp_responses.universe, [0, 0, 10])
        self.arp_responses['medium'] = fuzz.trimf(self.arp_responses.universe, [5, 15, 25])
        self.arp_responses['high'] = fuzz.trapmf(self.arp_responses.universe, [20, 30, MAX_ARP_RESPONSES, MAX_ARP_RESPONSES])

        # MAC Changes
        self.mac_changes['low'] = fuzz.trimf(self.mac_changes.universe, [0, 0, 1])
        self.mac_changes['medium'] = fuzz.trimf(self.mac_changes.universe, [1, 2, 3])
        self.mac_changes['high'] = fuzz.trapmf(self.mac_changes.universe, [2, 3, MAX_MAC_CHANGES, MAX_MAC_CHANGES])

        # Unsolicited Responses
        self.unsolicited_score['low'] = fuzz.trimf(self.unsolicited_score.universe, [0, 0, 20])
        self.unsolicited_score['medium'] = fuzz.trimf(self.unsolicited_score.universe, [10, 30, 50])
        self.unsolicited_score['high'] = fuzz.trapmf(self.unsolicited_score.universe, [40, 60, 100, 100])

        # IP Conflicts
        self.ip_conflicts['none'] = fuzz.trimf(self.ip_conflicts.universe, [0, 0, 1])
        self.ip_conflicts['few'] = fuzz.trimf(self.ip_conflicts.universe, [0, 1, 2])
        self.ip_conflicts['many'] = fuzz.trapmf(self.ip_conflicts.universe, [1, 2, MAX_IP_CLAIMS, MAX_IP_CLAIMS])

        # Threat Level
        self.threat_level['low'] = fuzz.trimf(self.threat_level.universe, [0, 0, 30])
        self.threat_level['medium'] = fuzz.trimf(self.threat_level.universe, [20, 50, 70])
        self.threat_level['high'] = fuzz.trapmf(self.threat_level.universe, [60, 80, 100, 100])

    def _setup_rules(self):
        # Определим все возможные термы для каждой переменной
        response_terms = ['low', 'medium', 'high']
        mac_change_terms = ['low', 'medium', 'high']
        unsolicited_terms = ['low', 'medium', 'high']
        ip_conflict_terms = ['none', 'few', 'many']
        
        # Весовые коэффициенты для каждого параметра
        weights = {
            'unsolicited': 1.5,
            'ip_conflicts': 1.3,
            'mac_changes': 1.0,
            'arp_responses': 0.8
        }
        
        # Уровни важности для каждого терма
        levels = {
            'arp_responses': {'low': 0, 'medium': 1, 'high': 2},
            'mac_changes': {'low': 0, 'medium': 1, 'high': 2},
            'unsolicited_score': {'low': 0, 'medium': 1, 'high': 2},
            'ip_conflicts': {'none': 0, 'few': 1, 'many': 2}
        }

        self.rules = []
        
        # Генерируем все возможные комбинации
        for r, m, u, i in product(response_terms, mac_change_terms, 
                                unsolicited_terms, ip_conflict_terms):
            # Вычисляем общий вес угрозы
            score = (weights['arp_responses'] * levels['arp_responses'][r] +
                    weights['mac_changes'] * levels['mac_changes'][m] +
                    weights['unsolicited'] * levels['unsolicited_score'][u] +
                    weights['ip_conflicts'] * levels['ip_conflicts'][i])
            
            # Определяем уровень угрозы на основе score
            if score >= 5.5:
                threat = self.threat_level['high']
            elif score >= 3.5:
                threat = self.threat_level['medium']
            else:
                threat = self.threat_level['low']
            
            # Создаем правило
            rule = ctrl.Rule(
                self.arp_responses[r] &
                self.mac_changes[m] &
                self.unsolicited_score[u] &
                self.ip_conflicts[i],
                threat
            )
            self.rules.append(rule)
        
        # Добавляем специальные правила для крайних случаев
        self.rules.extend([
            # Очень высокая угроза при сочетании нескольких критических параметров
            ctrl.Rule(
                (self.arp_responses['high'] & self.mac_changes['high']) |
                (self.unsolicited_score['high'] & self.ip_conflicts['many']),
                self.threat_level['high']
            ),
            
            # Снижаем угрозу для шлюзов
            ctrl.Rule(
                (self.ip_conflicts['none'] & self.unsolicited_score['medium']),
                self.threat_level['medium']
            ),
            
            # Повышаем угрозу при резких изменениях
            ctrl.Rule(
                (self.mac_changes['high'] & self.unsolicited_score['medium']),
                self.threat_level['high']
            )
        ])

    def analyze_cap(self, capture):
        arp_stats = defaultdict(lambda: {
            'requests': 0,
            'responses': 0,
            'unsolicited': 0,
            'mac_changes': defaultdict(int),  # Словарь для отслеживания изменений MAC
            'ip_claims': defaultdict(int),
            'last_request_time': None,
            'mac': None,
            'last_mac': None  # Добавляем поле для предыдущего MAC
        })
        
        ip_req = defaultdict()
        
        ip_mac_history = defaultdict(list)  # История MAC для каждого IP

        for packet in capture:
            if not hasattr(packet, 'arp'):
                continue

            src_ip = packet.arp.src_proto_ipv4
            src_mac = packet.arp.src_hw_mac
            packet_time = float(packet.sniff_timestamp)

            if src_ip in WHITELIST_IPS:
                continue

            # Запоминаем текущий MAC для IP
            ip_mac_history[src_ip].append((packet_time, src_mac))
            
            # Получаем статистику по MAC-адресу
            stats = arp_stats[src_mac]
            stats['mac'] = src_mac
            # Обновляем статистику запросов/ответов
            if packet.arp.opcode == '1':  # ARP request
                stats['requests'] += 1
                ip_req[packet.arp.dst_proto_ipv4] = packet_time
            elif packet.arp.opcode == '2':  # ARP response
                stats['responses'] += 1
                if (packet.arp.src_proto_ipv4 not in ip_req or ip_req[packet.arp.src_proto_ipv4] is None or
                    packet_time - ip_req[packet.arp.src_proto_ipv4] > UNSOLICITED_THRESHOLD):
                    stats['unsolicited'] += 1

            # Обновляем конфликты IP
            stats['ip_claims'][src_ip] += 1
            
            # Анализ изменений MAC (новый код)
            if stats['last_mac'] and stats['last_mac'] != src_mac:
                stats['mac_changes'][src_mac] += 1
            stats['last_mac'] = src_mac

        # Дополнительный анализ истории MAC (новый код)
        for ip, history in ip_mac_history.items():
            if len(history) < 2:
                continue
                
            # Сортируем по времени
            history.sort()
            
            # Проверяем изменения MAC для IP
            prev_mac = history[0][1]
            for time, mac in history[1:]:
                if mac != prev_mac:
                    # Записываем изменение в статистику нового MAC
                    if mac in arp_stats:
                        arp_stats[mac]['mac_changes'][prev_mac] += 1
                    prev_mac = mac

        # Анализ и оценка угроз
        results = []
        for mac, stats in arp_stats.items():
            if stats['responses'] == 0:
                continue

            # Количество разных IP, заявленных этим MAC
            ip_conflicts = len(stats['ip_claims'])
            
            # Количество изменений этого MAC (новый код)
            mac_change_count = len(stats['mac_changes'])
            
            # Вычисляем метрики
            metrics = self._calculate_metrics(stats, ip_conflicts, mac_change_count)
            threat = self._evaluate_threat(metrics)
            print('\n------------------------------------\n')
            # self.threat_level.view(sim=self.simulation)
            # plt.plot()
            print(f'THREAT: {threat}')
            results.append({
                'mac': mac,
                'threat': threat,
                'ip_conflicts': ip_conflicts,
                'mac_changes': mac_change_count,  # Добавляем в вывод
                'claimed_ips': list(stats['ip_claims'].keys()),
                'metrics': metrics,
                'stats': stats
            })

        print(results)
        results = sorted(results, key=lambda x: x['threat'], reverse=True)
        
        danger_info = (ARP_SPOOF, NEED_REPORT, results)
        return danger_info
        
        # return sorted(results, key=lambda x: x['threat'], reverse=True)

    def _calculate_metrics(self, stats, ip_conflicts, mac_change_count):
        """Вычисление всех метрик с учетом изменений MAC"""
        unsolicited_ratio = (stats['unsolicited'] / stats['responses']) * 100 if stats['responses'] > 0 else 0
        
        # Уменьшаем вес одиночных изменений MAC
        if mac_change_count == 1:
            mac_change_count = 0.5
            
        # Комбинированный score
        unsolicited_score = min(0.6 * unsolicited_ratio + 
                            0.2 * stats['unsolicited'] + 
                            0.2 * mac_change_count, 100)
        
        return {
            'arp_responses': min(stats['responses'], MAX_ARP_RESPONSES),
            'mac_changes': min(mac_change_count, MAX_MAC_CHANGES),
            'unsolicited_score': unsolicited_score,
            'ip_conflicts': min(ip_conflicts, MAX_IP_CLAIMS),
            'is_gateway': any(ip.endswith('.1') for ip in stats['ip_claims'])
        }

    def _evaluate_threat(self, metrics):
        """Оценка уровня угрозы с дополнительной логикой"""
        try:
            self.simulation.input['arp_responses'] = metrics['arp_responses']
            self.simulation.input['mac_changes'] = metrics['mac_changes']
            self.simulation.input['unsolicited_score'] = metrics['unsolicited_score']
            self.simulation.input['ip_conflicts'] = metrics['ip_conflicts']
            
            self.simulation.compute()
            threat = self.simulation.output['threat_level']
            self.arp_responses.view_user(sim=self.simulation)
            plt.ylabel('Величина принадлежности')
            plt.xlabel('Количество arp-ответов')
            plt.title('Оценка для терма "количество arp-ответов"')
            plt.show()
            self.mac_changes.view_user(sim=self.simulation)
            plt.ylabel('Величина принадлежности')
            plt.xlabel('количество изменений mac')
            plt.title('Оценка для терма "количество изменений mac"')
            plt.show()
            self.unsolicited_score.view_user(sim=self.simulation)
            plt.ylabel('Величина принадлежности')
            plt.xlabel('количество незапрошенных ответов')
            plt.title('Оценка для терма "количество незапрошенных ответов"')
            plt.show()
            self.ip_conflicts.view_user(sim=self.simulation)
            plt.ylabel('Величина принадлежности')
            plt.xlabel('количество конфликтующих ip')
            plt.title('Оценка для терма "количество конфликтующих ip"')
            plt.show()
            self.threat_level.view_user(sim=self.simulation)
            plt.ylabel('Величина принадлежности')
            plt.xlabel('Уровень угрозы')
            plt.title('Оценка для терма "уровень угрозы"')
            plt.show()
            
            # Дополнительные корректировки
            if metrics['is_gateway']:
                threat *= 0.8  # Снижаем угрозу для шлюза
                
            if metrics['ip_conflicts'] == 1 and metrics['unsolicited_score'] < 50:
                threat *= 0.7  # Снижаем угрозу для единичных конфликтов
                
            return min(threat, 100)
        except Exception as e:
            if DEBUG:
                print(f"Ошибка оценки угрозы: {e}")
            return 0
        
    def save(self, info):
        self.simulation.input['arp_responses'] = info['metrics']['arp_responses']
        self.simulation.input['mac_changes'] = info['metrics']['mac_changes']
        self.simulation.input['unsolicited_score'] = info['metrics']['unsolicited_score']
        self.simulation.input['ip_conflicts'] = info['metrics']['ip_conflicts']
        
        self.simulation.compute()
        self.threat_level.view_user(sim=self.simulation)
        plt.title('Результат распознавания потенциального\nARP-spoofing')
        plt.xlabel('Уровень потенциального ARP-spoofing')
        plt.ylabel('Функция принадлежности')
        plt.legend(['Низкий', 'Средний', 'Высокий'], loc='upper left')
        
        path = f'/home/alex/Coding/FuzzySystem/reports/images/fuzzy_danger_level_arp_spoof_{ARPSpoofingDetector.idx}.png'
        
        plt.savefig(path, dpi=300, bbox_inches='tight')
        
        ARPSpoofingDetector.idx += 1
        
        return path
    
    def lightweight_arp_spoofing_check(self, cap_fd, 
                            max_arp_packets=1000, 
                            max_unique_mac_ip_pairs=50, 
                            max_conflicts=3, 
                            sample_size=500):
        try:
            cap = pyshark.FileCapture(
                input_file=cap_fd,
                display_filter='arp',
                only_summaries=True,  # Быстрее, так как не загружаем полные пакеты
                keep_packets=False    # Не хранить пакеты в памяти для экономии
            )
            
            ip_to_mac = defaultdict(set)
            unique_pairs = set()
            arp_count = 0
            conflicts_detected = 0
            
            for pkt in cap:
                if not hasattr(pkt, 'arp') or not hasattr(pkt, 'eth'):
                    continue
                    
                arp_count += 1
                
                src_ip = pkt.arp.src_proto_ipv4
                src_mac = pkt.eth.src
                
                # Проверяем конфликты MAC-IP
                if src_ip in ip_to_mac:
                    if src_mac not in ip_to_mac[src_ip]:
                        conflicts_detected += 1
                        if conflicts_detected >= max_conflicts:
                            cap.close()
                            return True
                else:
                    ip_to_mac[src_ip].add(src_mac)
                
                # Отслеживаем уникальные пары MAC-IP
                unique_pairs.add((src_mac, src_ip))
                if len(unique_pairs) > max_unique_mac_ip_pairs:
                    cap.close()
                    return True
                
                # Досрочное прерывание если достигли лимита
                if arp_count >= max_arp_packets or arp_count >= sample_size:
                    break
                    
            cap.close()
            
            # Если обнаружено хотя бы несколько конфликтов
            return conflicts_detected >= 1
            
        except Exception as e:
            print(f"Error analyzing pcap: {e}")
            return False


if __name__ == "__main__":
    detector = ARPSpoofingDetector()
    
    # Пример 1: Анализ PCAP файла
    if DEBUG:
        print("[*] Analyzing pcap file...")
        # /home/alex/Coding/FuzzySystem/pcaps/arp-spoofing.pcapng
        cap = pyshark.FileCapture("/home/alex/Coding/FuzzySystem/pcaps/arp-spoofing.pcapng", display_filter="arp")
        # cap = pyshark.FileCapture("/home/alex/Coding/FuzzySystem/pcaps/arp-spoof/normal.pcapng", display_filter="arp")
        results = detector.analyze_cap(cap)[2]
        
        print("\nTop 5 potential threats:")
        for result in results[:5]:
            print(f"\nMAC: {result['mac']} | Threat: {result['threat']:.1f}%")
            print(f"Claimed IPs: {result['claimed_ips']}")
            print(f"Responses: {result['stats']['responses']} | Unsolicited: {result['metrics']['unsolicited_score']:.1f}%")
            print(f"MAC Changes: {result['stats']['mac_changes']} | IP Conflicts: {result['ip_conflicts']}")
