import shutil
import subprocess
import threading
import time
import fcntl
import os
import atexit

import sys
if sys.version_info >= (3, 12, 0):
    import six
    sys.modules['kafka.vendor.six.moves'] = six.moves

from kafka import KafkaProducer
from kafka import KafkaAdminClient
from kafka.admin import ConfigResource

PATH = '/home/alex/Coding/FuzzySystem/source_pcaps'
DEST_DIR = '/home/alex/Coding/FuzzySystem/copied_pcaps/'
WAIT_TIME = 2

IFACE = 'vboxnet0'
RETENTION_MS = 5000
KB_SIZE = 10

stop_event = threading.Event()
debug_idx = 1

class PcapSender:
    def __init__(self, broker, topic):
        self.kafka_broker = broker
        self.topic = topic
        self.producer = KafkaProducer(bootstrap_servers=self.kafka_broker)

        atexit.register(self.__del__)
    
    def __del__(self):
        print(f'PcapSender завершает работу ({os.getpid()})')
        self.producer.close()


    def send_pcap_file_to_kafka(self, pcap_file_path):
        """
        Отправляет pcap файл в Kafka.
        :param kafka_broker: Адрес Kafka брокера (например, "localhost:9092")
        :param topic: Название Kafka топика
        :param pcap_file_path: Путь к pcap файлу
        """
        
        try:
            # Читаем файл в бинарном режиме
            with open(pcap_file_path, "rb") as file:
                pcap_data = file.read()

            # Отправляем содержимое файла в Kafka
            self.producer.send(self.topic, pcap_data)
            print(f"Файл {pcap_file_path} успешно отправлен в Kafka топик '{self.topic}'")

        except Exception as e:
            print(f"Ошибка при отправке файла в Kafka: {e}")
            

    

class PcapMonitor:
    
    '''
    src_dir - исходная директория
    dest_dir - целевая директория
    wait_time - время, на которое процесс будет засыпать, между проверками
    '''
    def __init__(self, src_dir, dest_dir, wait_time):
        self.src_dir = src_dir
        self.dest_dir = dest_dir
        self.wait_time = wait_time
        self.broker = PcapSender('192.168.57.3:9092', 'pcap')
        atexit.register(self.__del__)
    
    def __del__(self):
        print(f'PcapMonitor завершает работу ({os.getpid()})')
        
    @staticmethod
    def _is_file_used_by_tshark(filepath):
        """Проверяет, используется ли файл процессом tshark через fuser"""
        try:
            result = subprocess.run(
                ["sudo", "fuser", "-v", filepath],
                encoding="utf8",
                capture_output=True,
            )
            # Если процесс tshark использует файл, он будет в выводе
            # ниже выводится номер pid, который использует файл
            # его не будет, если никто не использует файл
            print(f"USED: {result.stdout}")
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return False
    
    @staticmethod
    def _if_file_is_filled_up(filepath):

        file_size = os.path.getsize(filepath)
        print(f"Размер файла: {file_size} байт")

        return (file_size / 1000.0) >= KB_SIZE
    
    @staticmethod
    def _if_file_is_not_last():
        if len(os.listdir(PATH)) < 2:
            print("В директории меньше 2 файлов.")

    def monitor_unused_pcap_files(self):
        """Мониторит .pcap файлы и выводит неиспользуемые"""
        global debug_idx

        while not stop_event.is_set():
            all_pcaps = [
                os.path.join(self.src_dir, f)
                for f in os.listdir(self.src_dir)
                if f.endswith(".pcapng")
            ]

            unused_pcaps = [f for f in all_pcaps if self._is_file_used_by_tshark(f) == '']

            if unused_pcaps:
                print("Неиспользуемые .pcapng файлы:")
                for pcap in unused_pcaps:
                    file_name = pcap.split('/')[-1]
                    dest = os.path.join(self.dest_dir, file_name)
                    shutil.move(pcap, dest)
                    print(f"{debug_idx}: pcap")
                    debug_idx+=1
                    self.broker.send_pcap_file_to_kafka(dest)
                    os.remove(dest)
            else:
                pass
                print("Файлов нет или все .pcapng файлы используются tshark")

            time.sleep(2)  # Проверка каждые 2 секунды
            
class Sniffer:
    
    def __init__(self, src_dir, iface):
        self.src_dir = src_dir
        self.iface = iface
        
        atexit.register(self.__del__)
    
    def __del__(self):
        print(f'Sniffer завершает работу ({os.getpid()})')

    def start_tcpdump(self):
        try:
            p = subprocess.Popen(
                [
                    "tshark",
                    # "-i", "vboxnet0",
                    "-i", f"{self.iface}",
                    "-F", "pcapng",
                    "-w", f"{self.src_dir}/mycap.pcapng",
                    # "-b", f"duration:10",
                    # "-b", f"files:2"
                    "-b" f"filesize:{KB_SIZE}"
                ],
                stdout=subprocess.PIPE,
            )
        except Exception as e:
            print(f"Ошибка при запуске tcpdump: {e}")
        
        return p

def create_monitor():
    try:
        monitor = PcapMonitor(PATH, DEST_DIR, WAIT_TIME)
        monitor.monitor_unused_pcap_files()
    finally:
        stop_event.set()
        
def create_sniffer():
    sniffer = None
    p = None
    try:
        sniffer = Sniffer(PATH, IFACE)
        p = sniffer.start_tcpdump()
    except:
        stop_event.set()
        
    return p, sniffer
        
        
def make_dir():
    if not os.path.exists(PATH):
        os.makedirs(PATH)

if __name__ == '__main__':
    make_dir()

    thread = threading.Thread(target=create_monitor, daemon=True)
    thread.start()
    
    # Если не забирать sniffer, то создается два экземпляра
    sniffer_process, sniffer = create_sniffer()
    while True:
        if stop_event.is_set():
            sniffer_process.terminate()
            thread.join(timeout=5)
            break
        
        retcode = sniffer_process.poll()  # Проверяем статус
        if retcode is not None:
            stop_event.set()
            print(f"Процесс завершился с кодом {retcode}")
        else:
            time.sleep(5)  # Проверяем каждые 5 секунд
