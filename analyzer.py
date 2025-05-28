import os
import shutil
from threading import Thread
import concurrent
import pyshark
import multiprocessing
from multiprocessing import Process
import time
from thread_pool_manager import ThreadPoolManager
from process_pool_manager import ProcessPoolManager
from cap_manager import CapManager
from port_scan import PortScan
from arp_analyzer_v4 import ARPSpoofingDetector
from dns_tun_analyzer_v4 import DNSTunnelDetector
import socket
import matplotlib
from INFO import *
import timeit
from report_generator import ReportGenerator

# IP_PROTO.get(int(packet.ip.proto)) --> TCP
# {0: 'HOPOPTS', 1: 'ICMP', 2: 'IGMP', 41: 'IPV6', 4: 'IPIP', 6: 'TCP', 8: 'EGP', 12: 'PUP', 17: 'UDP', 136: 'UDPLITE', 22: 'IDP', 29: 'TP', 43: 'ROUTING', 44: 'FRAGMENT', 46: 'RSVP', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPV6', 59: 'NONE', 60: 'DSTOPTS', 103: 'PIM', 132: 'SCTP', 262: 'MPTCP', 255: 'RAW'}
IP_PROTO={v:k[8:] for (k,v) in vars(socket).items() if k.startswith('IPPROTO')}
print(IP_PROTO)

THREADS = multiprocessing.cpu_count() # 16
CAP_DIR = "/home/alex/Coding/FuzzySystem/pcaps/nmap"
PROCESSED_DIR = "/home/alex/Coding/FuzzySystem/pcaps/processed"
DEBUG = 1

OK = 0
FAIL = 1

def check_flag_syn(flags):
    if len(flags) == 1 and flags[0] == SYN:
        return True
    
    return False

# tcp_flags = packet.tcp.flags.hex_value
def get_flags_of_packet(tcp_flags):
    flags = set()
    if tcp_flags & FIN:
        flags.add(FIN)
    if tcp_flags & SYN:
        flags.add(SYN)
    if tcp_flags & RST:
        flags.add(RST)
    if tcp_flags & PSH:
        flags.add(PSH)
    if tcp_flags & ACK:
        flags.add(ACK)
    if tcp_flags & URG:
        flags.add(URG)
    if tcp_flags & ECE:
        flags.add(ECE)
    if tcp_flags & CWR:
        flags.add(CWR)
    
    if len(flags) == 0:
        print("[ERROR]: get_flags_of_packet is empty")


    
        
def task_to_run(arg1, arg2):
    # Обработка полученного аргумента
    print("task")
    time.sleep(2)
    return ('icmp', {'danger': 95})
        
def _wait_callback(future):
    if future.result() != OK:
        print('[ERROR]: wait task is not OK!')
    if DEBUG:
        print('[DEBUG]: wait task is OK!')

class Analyzer:
    
    def __init__(self):
        os.environ['ReportPortScanIdx'] = str(0)
        self.cap_manager = CapManager()
        self.cap_fd = None
        self.thread_pool = ThreadPoolManager()
        self.port_scan = PortScan()
        self.arp_scan = ARPSpoofingDetector()
        self.dns_tun = DNSTunnelDetector()
        self.run_flag = True
        
    def _wait_for_futures(self, pcap_file, pcap_fd, futures):
        matplotlib.use('agg')
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            filter_tag = res[0]
            need_report = res[1]
            info = res[2]
            print(info)
            if need_report:
                if filter_tag == PORT_SCAN:
                    path = self.port_scan.save(info)
                elif filter_tag == ARP_SPOOF:
                    path = self.arp_scan.save(info[0])
                elif filter_tag == DNS_TUN:
                    path = self.dns_tun.save(info[0])
                ReportGenerator.generate_report(filter_tag, info, path)
        
        pcap_fd.close()
        self.cap_manager.move_cap_to_processed(pcap_file)
            
        self.run_flag = False

        return OK

    
    # Если по каким-то причинам thread_pool не будет работать, то
    # 1. Используй process_pool
    # 2. Передавай pcap_path, вместо cap_fd
    # 3. Измени _wait_for_futures
    def analyze(self):
        futures = []
        self.cap_fd = self.cap_manager.get_first_cap()
        
        need_scan = self.port_scan.check_for_scan(self.cap_fd)
        need_arp = self.arp_scan.lightweight_arp_spoofing_check(self.cap_manager.get_current_cap_path())
        # cap = pyshark.FileCapture("/home/alex/Coding/FuzzySystem/pcaps/dns/solo_dns.pcapng")
        need_dns = self.dns_tun.lightweight_dns_tunnel_check(cap)
        print(f"NEED_DNS: {need_dns}")

        if need_scan:
            cap = pyshark.FileCapture(self.cap_manager.get_current_cap_path(), keep_packets=False, display_filter=PortScan.get_filter())
            futures.append(self.thread_pool.submit_task(PortScan().analyze_cap, cap))
        
        if need_arp:
            cap = pyshark.FileCapture(self.cap_manager.get_current_cap_path(), display_filter="arp")
            futures.append(self.thread_pool.submit_task(ARPSpoofingDetector().analyze_cap, cap))
            
        if need_dns:
            cap = pyshark.FileCapture(self.cap_manager.get_current_cap_path(), display_filter='dns && dns.flags.response==0 && ip')
            futures.append(self.thread_pool.submit_task(DNSTunnelDetector().analyze_cap, cap))
            
        
        # Запускаем отдельный поток для ожидания результатов
        # Не берем wait_future, потому что отслеживаем его состояние через wait_callback
        if futures:                     
            self.thread_pool.submit_task(self._wait_for_futures,
                                        self.cap_manager.get_current_cap_path(),
                                        self.cap_fd,
                                        futures,
                                        callback=_wait_callback)
        while self.run_flag:
            time.sleep(1)
    
    def check_for_ports_scanning(): # --> return true/false (true=есть пакеты для анализа на скан)
        pass
    
    def check_for_arp_spoofing(): # --> return true/false (true=есть пакеты для анализа на спуф)
        pass

def main():
    # counter = 0
    # cap = pyshark.FileCapture(f'/home/alex/Coding/FuzzySystem/pcaps/nmap/data_{counter}.pcapng')
    analyzer = Analyzer()
    analyzer.analyze()
    


if __name__ == "__main__":
    main()
