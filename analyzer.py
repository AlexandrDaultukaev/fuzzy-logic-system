import os
import shutil
from threading import Thread
import concurrent
import pyshark
import multiprocessing
from multiprocessing import Process
import time
from thread_pool_manager import ThreadPoolManager
from cap_manager import CapManager
from port_scan_module import PortScanDetector
from arp_spoof_module import ARPSpoofingDetector
from dns_tun_module import DNSTunnelDetector
import socket
import matplotlib
from CONFIG_INFO import *
import timeit
from report_generator import ReportGenerator

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

IP_PROTO={v:k[8:] for (k,v) in vars(socket).items() if k.startswith('IPPROTO')}

THREADS = multiprocessing.cpu_count() # 16
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
        self.port_scan = PortScanDetector()
        self.arp_spoof = ARPSpoofingDetector()
        self.dns_tun = DNSTunnelDetector()
        self.run_flag = True
        self.wait_ended = False
        
        print('[Analyzer] is inited successfully')
        
    def _wait_for_futures(self, pcap_file, pcap_fd, futures):
        matplotlib.use('agg')
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            filter_tag = res[0]
            need_report = res[1]
            info = res[2]

            if need_report:
                if filter_tag == PORT_SCAN:
                    path = self.port_scan.save(info)
                elif filter_tag == ARP_SPOOF:
                    path = self.arp_spoof.save(info[0])  # По нулевому индексу хранится
                                                        # наиболее опасная запись
                                                        # поэтому функцию п. генерируем только для нее
                elif filter_tag == DNS_TUN:
                    if len(info):
                        path = self.dns_tun.save(info[0])
                ReportGenerator.generate_report(filter_tag, info, path)
        
        self.wait_ended = True
        pcap_fd.close()
        # self.cap_manager.move_cap_to_processed(pcap_file)
            
        # self.run_flag = False

        return OK

    def analyze(self):
        self.cap_fd = self.cap_manager.get_first_cap()
        
        while self.run_flag:
            futures = []
            
            need_scan = self.port_scan.check_for_scan(self.cap_fd)
            need_arp = self.arp_spoof.fast_arp_spoofing_check(self.cap_fd)
            print(f"{self.cap_manager.get_current_cap_path()}")
            need_dns = self.dns_tun.lightweight_dns_tunnel_check_v2(self.cap_manager.get_current_cap_path())
            
            # self.cap_fd = pyshark.FileCapture(f'/home/alex/Coding/FS/pcaps/active/data_69.pcapng')
            # self.cap_manager.file_in_process_path="/home/alex/Coding/FS/pcaps/active/data_69.pcapng"
            
            print(
            f'''
            {"🟢 "+bcolors.OKGREEN if need_scan else "🔴 "+bcolors.FAIL}Полная проверка на СКАНИРОВАНИЕ{bcolors.ENDC}
            {"🟢 "+bcolors.OKGREEN if need_arp else "🔴 "+bcolors.FAIL}Полная проверка на ARP-spoofing{bcolors.ENDC}
            {"🟢 "+bcolors.OKGREEN if need_dns else "🔴 "+bcolors.FAIL}Полная проверка на DNS-туннелирование{bcolors.ENDC}
            ''')

            if need_scan:
                cap = pyshark.FileCapture(self.cap_manager.get_current_cap_path(), keep_packets=False, display_filter=PortScanDetector.get_filter())
                futures.append(self.thread_pool.submit_task(PortScanDetector().analyze_cap, cap))
            
            if need_arp:
                cap = pyshark.FileCapture(self.cap_manager.get_current_cap_path(), display_filter=ARPSpoofingDetector.get_filter())
                futures.append(self.thread_pool.submit_task(ARPSpoofingDetector().analyze_cap, cap))
                
            if need_dns:
                cap = pyshark.FileCapture(self.cap_manager.get_current_cap_path(), display_filter=DNSTunnelDetector.get_filter())
                futures.append(self.thread_pool.submit_task(DNSTunnelDetector().analyze_cap, cap))
                
            self.wait_ended = False
            # Запускаем отдельный поток для ожидания результатов
            # Не берем wait_future, потому что отслеживаем его состояние через wait_callback
            if futures:
                cap = self.cap_fd
                path = self.cap_manager.get_current_cap_path()
                fut = futures.copy()
                self.thread_pool.submit_task(self._wait_for_futures,
                                            path,
                                            cap,
                                            fut,
                                            callback=_wait_callback)
            else:
                self.cap_fd.close()
                
            if futures:
                while not self.wait_ended:
                    time.sleep(1)

            self.cap_fd = self.cap_manager.next_cap()

def main():
    # counter = 0
    # cap = pyshark.FileCapture(f'/home/alex/Coding/FuzzySystem/pcaps/nmap/data_{counter}.pcapng')
    analyzer = Analyzer()
    analyzer.analyze()
    


if __name__ == "__main__":
    main()
