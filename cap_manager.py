import os
import shutil
import time
import pyshark
from CONFIG_INFO import *

# CAP_DIR = "/home/alex/Coding/FuzzySystem/pcaps/nmap"
# PROCESSED_DIR = "/home/alex/Coding/FuzzySystem/pcaps/processed"
DEBUG = 1

class CapManager:
    
    INIT_COUNTER = 0
    
    def __init__(self):

        self.counter = CapManager.INIT_COUNTER
        self.file_in_process_path = ""
        self.cap_fd = None
        
        os.makedirs(PROCESSED_DIR, exist_ok=True)
        print('[CapManager] is inited successfully')
        
    def __del__(self):
        self.__close_processed_cap()
    
    def __inc_counter(self):
        self.counter += 1
    

    def __update_fd(self, filter="", only_summaries=False):
        file_in_process_tmp = f"{CAP_DIR}data_{self.counter}.pcapng"
        self.file_in_process_path = ""
        while not os.path.exists(file_in_process_tmp):
            if DEBUG:
                print(f"[DEBUG]: {file_in_process_tmp} waiting")
            time.sleep(1)
        if os.path.isfile(file_in_process_tmp):
            self.file_in_process_path = file_in_process_tmp
            self.cap_fd = pyshark.FileCapture(self.file_in_process_path, display_filter=filter)#, only_summaries=only_summaries)
        else:
            print(f"[ERROR]: {file_in_process_tmp} is not a file!")
        if DEBUG:
            print(f"[DEBUG]: {self.file_in_process_path} opened")
            
    def __close_processed_cap(self):
        if DEBUG:
            print(f"[DEBUG]: {self.file_in_process_path} closed")
        if self.file_in_process_path:
            self.cap_fd.close()

    def move_cap_to_processed(self, filename):
        if DEBUG:
            print(f"[DEBUG]: {filename} --> {PROCESSED_DIR}{filename.split('/')[-1]}")
        shutil.move(filename, PROCESSED_DIR)

    def get_current_cap_path(self):
        return self.file_in_process_path

    def get_first_cap(self):
        if self.file_in_process_path != f"{CAP_DIR}/data_{self.counter}.pcapng":
            self.__update_fd()
        else:
            print(f"[ERROR]: {self.file_in_process_path} is already opened!")
            return None
        
        return self.cap_fd
    
    def next_cap(self):
        
        # self.__close_processed_cap()
        self.__inc_counter()
        self.__update_fd()
        
        return self.cap_fd
        