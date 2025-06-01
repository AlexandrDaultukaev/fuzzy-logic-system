# О системе

Система мониторинга сетевого трафика с использованием алгоритмов нечеткой логики. Реализует проверки на следующие типы атак:

* Порт-сканирование;
* ARP-spoofing;
* DNS-туннелирование.

# Prerequisites

* Kafka, Zookeeper.
* см. requirements.txt

# Первоначальная настройка

Следует установить в cfg.ini корректные пути и ip-адрес сервера, с которого будут стягиваться pcap-файлы.

# Запуск системы

На сервере запускается tshark_sniffer.py;
На хосте-анализаторе запускается read_pcaps.py и analyzer.py;

# Пример работы программы

```
> python3 analyzer.py
[CapManager] is inited successfully
[ThreadPoolManager] is inited successfully (CPU_COUNT: 5)
[PortScanDetector] is inited successfully
[ARPSpoofingDetector] is inited successfully
[DNSTunnelDetector] is inited successfully
[Analyzer] is inited successfully
[DEBUG]: /home/user/pcaps/active/data_0.pcapng opened

🟢 Полная проверка на СКАНИРОВАНИЕ
🟢 Полная проверка на ARP-spoofing
🔴 Полная проверка на DNS-туннелирование

Отчет сохранен: /home/user/reports/arp_spoof_report_0.html
```



