import configparser

config = configparser.ConfigParser()
config.read('/home/alex/Coding/FS/cfg.ini')

print(config.sections())

SERVER_IP = config['common']['ServerIp']
CAP_DIR = config['common']['CapDir']
PROCESSED_DIR = config['common']['ProcessedDir']
REPORT_DIR = config['common']['ReportDir']
REPORT_IMAGES_DIR = config['common']['ReportImagesDir']
PCAP_DIR_ADV = config['advanced']['PcapDir']
JSON_DIR = config['advanced']['ResJsonDir']

print(f'{SERVER_IP=}, {JSON_DIR=}')

NEED_REPORT = True
NO_NEED_REPORT = False

PORT_SCAN = 1
ARP_SPOOF = 2
DNS_TUN = 3

TCP = 0x06

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80