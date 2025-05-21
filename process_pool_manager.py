from concurrent.futures import ProcessPoolExecutor
from multiprocessing import cpu_count
from typing import Callable, Any


class ProcessPoolManager:
    def __init__(self, max_workers: int | None = None):
        """
        Инициализация пула процессов.
        
        :param max_workers: Максимальное количество процессов. По умолчанию - количество CPU.
        """
        self.max_workers = max_workers if max_workers is not None else cpu_count()
        self.executor = ProcessPoolExecutor(max_workers=self.max_workers)
    
    def __del__(self):
        """
        Деструктор - корректное завершение работы пула процессов.
        """
        self.executor.shutdown(wait=True)
    
    def submit_task(
        self,
        task: Callable,
        *args: Any,
        callback: Callable[[Any], None] | None = None
    ) -> Any:
        """
        Запускает задачу в отдельном процессе.
        
        :param task: Функция для выполнения
        :param args: Аргументы функции
        :param callback: Функция обратного вызова, которая будет вызвана с результатом
        :return: Future объект
        """
        future = self.executor.submit(task, *args)
        if callback is not None:
            future.add_done_callback(callback)
        return future

    def shutdown(self, wait: bool = True) -> None:
        """
        Явное завершение работы пула процессов.
        
        :param wait: Если True, дожидается завершения всех задач
        """
        self.executor.shutdown(wait=wait)