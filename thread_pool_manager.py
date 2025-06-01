from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import multiprocessing

CPU_COUNT = multiprocessing.cpu_count() # 16

class ThreadPoolManager:
    
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=CPU_COUNT//3)
        
        print(f'[ThreadPoolManager] is inited successfully (CPU_COUNT: {CPU_COUNT//3})')
        
    def __del__(self):
        self.executor.shutdown()
        
    def submit_task(self, task_to_run, *args, callback=None):
        future = self.executor.submit(task_to_run, *args)
        if callback:
            future.add_done_callback(callback)
        return future
    
    def submit_wait_task(self, task_to_run, *args, callback=None):
        future = self.executor.submit(task_to_run, *args)
        if callback:
            future.add_done_callback(callback)

        ok = concurrent.futures.wait([future])        
        
        if future in ok.done:
            print('[DEBUG]: Получен результат wait-task!')
            return future.result()
        else:
            print('[ERROR]: submit_wait_task future is not ok')
            return None
