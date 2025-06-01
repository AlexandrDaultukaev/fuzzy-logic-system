from os import listdir
import numpy as np
import matplotlib.pyplot as plt
import skfuzzy as fuzz
from skfuzzy import interp_membership
from skfuzzy import control as ctrl
from rule_maker import RuleMaker
from CONFIG_INFO import *
from collections import defaultdict
import pyshark
import asyncio
import sys
from os.path import isfile, join

DEBUG = 0
DEFAULT_FILTER = f"ip.dst == {SERVER_IP} and tcp"
PACKETS_PER_SECOND_LIMIT = 100
COUNT_THRESHOLD = 20
PORTS_THRESHOLD = 10
DANGER_THRESHOLD = 68
MAX_PACKETS = 130
MAX_PORTS = 100
MAX_SPEED = 300

# TODO: Реализовать следующие проверки
# Количество пакетов от одного хоста (Packet_Count)
#     Низкое (Low) – небольшое количество пакетов (например, 1–10).
#     Среднее (Medium) – умеренное количество (10–100).
#     Высокое (High) – аномально большое (100+).

# Количество уникальных портов за интервал времени (Port_Count)
#     Низкое (Low) – небольшое количество портов (например, 1–10).
#     Среднее (Medium) – умеренное количество (10–100).
#     Высокое (High) – аномально большое (100+).

# Скорость запросов (Packet_Rate)
#     Низкая (Low) – редкие запросы (например, <10 пакетов/сек).
#     Средняя (Medium) – умеренная скорость (10–100 пакетов/сек).
#     Высокая (High) – очень быстрая отправка (>100 пакетов/сек).

# ----- Углубленная проверка -----
# Количество ответов RST (ответ хоста о том, что порт закрыт attacker <-- host)
#     Низкое (Low) – небольшое количество портов (например, 1–10).
#     Среднее (Medium) – умеренное количество (10–100).
#     Высокое (High) – аномально большое (100+).

# Количество запросов SYN (запрос клиента на соединение  attacker --> host)
#     Низкое (Low) – небольшое количество портов (например, 1–10).
#     Среднее (Medium) – умеренное количество (10–100).
#     Высокое (High) – аномально большое (100+).
# ----- -------------------- -----

i = 0
def get_danger_term_from_ruler(packets_term, ports_term, speed_term):
    ruler = {
                'low low low': 'low',
                'low low medium': 'low',
                'low low high': 'low',
                'low low extremely high': 'medium',
                'low medium low': 'low',
                'low medium medium': 'medium',
                'low medium high': 'medium',
                'low medium extremely high': 'high',
                'low high low': 'medium',
                'low high medium': 'medium',
                'low high high': 'high',
                'low high extremely high': 'high',
                'medium low low': 'low',
                'medium low medium': 'medium',
                'medium low high': 'medium',
                'medium low extremely high': 'medium',
                'medium medium low': 'medium',
                'medium medium medium': 'medium',
                'medium medium high': 'medium',
                'medium medium extremely high': 'high',
                'medium high low': 'high',
                'medium high medium': 'high',
                'medium high high': 'high',
                'medium high extremely high': 'high',
                'high low low': 'medium',
                'high low medium': 'medium',
                'high low high': 'high',
                'high low extremely high': 'high',
                'high medium low': 'high',
                'high medium medium': 'high',
                'high medium high': 'high',
                'high medium extremely high': 'high',
                'high high low': 'critical',
                'high high medium': 'critical',
                'high high high': 'critical',
                'high high extremely high': 'critical',
            }
    global i
    rule = ruler[f'{packets_term} {ports_term} {speed_term}']
    if DEBUG:
        print(f"rule{i}: {packets_term} & {ports_term} & {speed_term} --> {rule}")
    i += 1
    return rule

class PortScanDetector:
    
    idx = 0
    
    def __init__(self):
        self.packets = ctrl.Antecedent(np.arange(0, MAX_PACKETS + 1, 1), 'number of packets from one IP, in hundreds')
        self.unique_ports = ctrl.Antecedent(np.arange(0, MAX_PORTS + 1, 1), 'number of unique ports')
        self.speed = ctrl.Antecedent(np.arange(0, MAX_SPEED + 1, 1), 'speed packets per sec')
        
        self.danger = ctrl.Consequent(np.arange(0, 101, 1), 'level of potential threat', defuzzify_method='centroid')
        
        self.packets['low'] = fuzz.trimf(self.packets.universe, [0, 0, 10])
        self.packets['medium'] = fuzz.trimf(self.packets.universe, [7, 50, 100])
        self.packets['high'] = fuzz.trapmf(self.packets.universe, [70, 100, MAX_PACKETS, MAX_PACKETS])
        
        self.unique_ports['low'] = fuzz.trimf(self.unique_ports.universe, [0, 0, 10])
        self.unique_ports['medium'] = fuzz.trimf(self.unique_ports.universe, [8, 20, 50])
        self.unique_ports['high'] = fuzz.trapmf(self.unique_ports.universe, [40, 60, MAX_PORTS, MAX_PORTS])
        
        self.speed['low'] = fuzz.trimf(self.speed.universe, [0, 3, 20])
        self.speed['medium'] = fuzz.trimf(self.speed.universe, [17, 50, 100])
        self.speed['high'] = fuzz.trimf(self.speed.universe, [80, 150, 200])
        self.speed['extremely high'] = fuzz.trapmf(self.speed.universe, [180, 250, MAX_SPEED, MAX_SPEED])
        
        self.danger['low'] = fuzz.trimf(self.danger.universe, [0, 0, 20])
        self.danger['medium'] = fuzz.trimf(self.danger.universe, [15, 30, 45])
        self.danger['high'] = fuzz.trimf(self.danger.universe, [25, 40, 80])
        self.danger['critical'] = fuzz.trapmf(self.danger.universe, [70, 90, 100, 100])
        
        ant_terms = [
                        ['low', 'medium', 'high'], # packets 
                        ['low', 'medium', 'high'],  # unique_ports
                        ['low', 'medium', 'high', 'extremely high']  # speed
                    ]
        rule_maker = RuleMaker()
        rules = rule_maker.make_rules([self.packets, self.unique_ports, self.speed], self.danger, ant_terms, get_danger_term_from_ruler)
        
        self.danger_ctrl = ctrl.ControlSystem(rules)
        self.danger_sim = ctrl.ControlSystemSimulation(self.danger_ctrl)
        
        print('[PortScanDetector] is inited successfully')
    
    @staticmethod
    def get_filter():
        return DEFAULT_FILTER
    
    def check_for_scan(self, cap):
        SYN_THRESHOLD = 5
        DELIMETER = 3
        RST_THRESHOLD = 10
        src_set = set()
        ip_map = dict()
        rst_counter = 0
        packet_num = 0
        for packet in cap:
            # Если нет аттрибута ip, значит это L2
            if not hasattr(packet, 'ip'):
                continue
            packet_num += 1
            if int(packet.ip.proto) == TCP:
                flags = packet.tcp.flags.hex_value
                # Если много RST -> true
                if flags & RST and packet.ip.src == SERVER_IP:
                    rst_counter += 1
                    if rst_counter >= RST_THRESHOLD:
                        return True
                # Если много SYN от одного ip -> true
                elif flags & SYN and packet.ip.src != SERVER_IP:
                    if packet.ip.src in src_set:
                        ip_map[packet.ip.src] += 1
                        if ip_map[packet.ip.src] >= SYN_THRESHOLD:
                            return True
                    else:
                       src_set.add(packet.ip.src)
                       ip_map[packet.ip.src] = 1
        
        # Если есть много различных src ip адресов с SYN, то вероятно, это распределенное сканирование
        if packet_num > 100 and packet_num // DELIMETER <= len(src_set):
            return True    
        
        return False
        
    
    # TODO ЕСЛИ L2, то не надо анализировать
    def analyze_cap(self, cap):
        # path = '/home/alex/Coding/FuzzySystem/pcaps/dns/solo_dns.pcapng'
        # cap = pyshark.FileCapture(path, keep_packets=False)#, display_filter=DEFAULT_FILTER)
        
        packets_count = defaultdict(int)
        packets_count_extra = defaultdict(int)
        time = 0
        # return 0
        # cap.load_packets()
        # packet_amount = len(cap)
        # print(packet_amount)
        try:
            for packet in cap:
                if packet.tcp.flags.hex_value & RST:
                    continue
                # print(packet)
            # ------ Формируем количество пакетов от одного хоста за определенное время ------
                time = round(float(packet.frame_info.time_relative))
                src_ip = packet.ip.src
                ports_set = set()
                if src_ip in packets_count_extra:
                    ports_set = packets_count_extra[src_ip][2]
                    
                # Не проверяем отсутствующее значение, потому что defaultdict
                packets_count[src_ip] += 1
            # --------------------------------------------------------------------------------
            # ------ Формируем количество запрошенных уникальных портов ----------------------
                ports_set.add(packet.tcp.dstport)
                packets_count_extra[src_ip] = (packets_count[src_ip], time, ports_set)

            
            
            # --------------------------------------------------------------------------------
                
            # ------ Проверяем на лимит ------------------------------------------------------
                if packets_count[src_ip] // int(time + 1) == PACKETS_PER_SECOND_LIMIT:
                    # Досрочное окончание проверки на сканирование
                    # Из-за достаточных данных, позволяющих судить о сканировании
                    # Если количество пакетов в одну секунду > 100, то высока вероятность сканирования
                    print(f'[DEBUG]: limit has reached! {packets_count[src_ip]} for {src_ip}')
                    break
            # --------------------------------------------------------------------------------
                # if DEBUG:
                #     print(packets_count)
                #     print(ports_set)
                #     print(packet.ip.dst)          # Убедитесь, что только 192.168.56.101
                #     print(f'{packet.tcp.srcport} -> {packet.tcp.dstport}')
        except Exception as e:
            print(f"Error in packet iteration: {e}")
        
        danger = 0
        max_danger_info = (PORT_SCAN, danger, None, 0, 0, 0)
        for ip, count_time_ports in packets_count_extra.items():
            count = count_time_ports[0]
            time = count_time_ports[1]
            ports = len(count_time_ports[2])
            speed = count // (time + 1) # time may be zero
            
            if count < COUNT_THRESHOLD or ports < PORTS_THRESHOLD:
                continue
            
            danger = self.get_result(count, ports, speed)
            if max_danger_info[0] < danger:
                max_danger_info = (danger, ip, count, ports, speed)
            if danger > DANGER_THRESHOLD:
                cap.close()
                return (PORT_SCAN, NEED_REPORT, max_danger_info)
            
        
        cap.close()
        
        return (PORT_SCAN, NO_NEED_REPORT, max_danger_info)
    
    def get_result(self, packets, u_ports, speed):
        try:
            self.danger_sim.input['number of packets from one IP, in hundreds'] = packets
            self.danger_sim.input['number of unique ports'] = u_ports
            self.danger_sim.input['speed packets per sec'] = speed
            self.danger_sim.compute()
            # self.danger_sim.print_state()
        except Exception as e:
            print(f"Error in getting result: {e}")

        return self.danger_sim.output['level of potential threat']
    
    def save(self, info):
        self.danger_sim.input['number of packets from one IP, in hundreds'] = info[2]
        self.danger_sim.input['number of unique ports'] = info[3]
        self.danger_sim.input['speed packets per sec'] = info[4]
        self.danger_sim.compute()
        self.danger.view_user(sim=self.danger_sim)
        plt.title('Результат распознавания потенциального\nсканирования')
        plt.xlabel('Уровень потенциального сканирования')
        plt.ylabel('Функция принадлежности')
        plt.legend(['Низкий', 'Средний', 'Высокий', 'Критический'], loc='upper left')
        
        path = f'/home/alex/Coding/FuzzySystem/reports/images/fuzzy_danger_level_port_scan_{PortScanDetector.idx}.png'
        
        plt.savefig(path, dpi=300, bbox_inches='tight')
        
        PortScanDetector.idx += 1
        
        return path

    
    def view(self):
        self.danger.view(sim=self.danger_sim)
        plt.show()

    def print_rule_objects(self):
        """Выводит техническую информацию о правилах"""
        for i, rule in enumerate(self.danger_ctrl.rules, 1):
            print(f"\nRule object #{i}:")
            print(f"Antecedent: {rule.antecedent}")
            print(f"Consequent: {rule.consequent}")

#
#
#
#
#

if __name__ == "__main__":    
    ps = PortScanDetector()
    # ps.packets.view()
    # plt.show()

    
    CUR_DIR = '/home/alex/Coding/FuzzySystem/pcaps/port_scan/'
    
    onlyfiles = [f for f in listdir(CUR_DIR)]
    for file in onlyfiles:
        ps = PortScanDetector()
        # cap = pyshark.FileCapture("/home/alex/Coding/FuzzySystem/pcaps/port_scan/SU Scan.pcapng", display_filter="tcp")
        cap = pyshark.FileCapture(join(CUR_DIR, file), display_filter='tcp')
        results = ps.analyze_cap(cap)[2][0]
        exit(1)
    
        
    
    # print(ps.get_result(200, 15, 15))
    ps.view()
    # ps.analyze_cap("f")
    