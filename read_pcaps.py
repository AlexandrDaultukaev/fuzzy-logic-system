import sys
if sys.version_info >= (3, 12, 0):
    import six
    sys.modules['kafka.vendor.six.moves'] = six.moves
from kafka import KafkaConsumer

from CONFIG_INFO import *

class PcapReciever:
    
    def __init__(self, broker, topic):
        self.kafka_broker = broker
        self.topic = topic
        self.idx = 0
        self.prefix = f'{CAP_DIR}data_'
        self.postfix = '.pcapng'
        # Инициализация Kafka Consumer
        self.consumer = KafkaConsumer(
            self.topic,
            bootstrap_servers=self.kafka_broker,
            auto_offset_reset="earliest",  # Начать с самого первого сообщения
            enable_auto_commit=True,
            group_id="pcap_group"
        )

    def receive_pcap_file_from_kafka(self):
        """
        Принимает pcap файл из Kafka и сохраняет его.
        :param kafka_broker: Адрес Kafka брокера (например, "localhost:9092")
        :param topic: Название Kafka топика
        :param output_file_path: Путь для сохранения pcap файла
        """
        
        try:
            print(f"Ожидание сообщений из топика '{self.topic}'...")
            output_file_path = self.prefix + str(self.idx) + self.postfix
            for message in self.consumer:
                # Сохраняем полученные данные в файл
                with open(output_file_path, "wb") as file:
                    file.write(message.value)
                    self.idx += 1
                print(f"Файл успешно сохранён как {output_file_path}")
                break  # Завершаем после получения первого сообщения

        except Exception as e:
            print(f"Ошибка при получении файла из Kafka: {e}")

receiver = PcapReciever('192.168.57.3:9092', 'pcap')
while True:
    receiver.receive_pcap_file_from_kafka()