from queue import Queue
from typing import List, Dict
from backend import Backends
from threading import Thread


class SecurityAlertQueueEvent:
    """queued events when an alert"""
    backends: Backends
    event: List[Dict]

    def __init__(self, backends: Backends, event: List[Dict]):
        """
        initialize the alert event
        :param backends: list of backends to dispatch alerts
        :param event: event to be triggered
        """
        self.backends = backends
        self.event = event


def dequeue(i: int, q: Queue):
    """
    workers use that target function to handle alerts
    :param i: thread number
    :param q: queue to pull
    """
    while True:
        queue_event = q.get()
        iter_backends = queue_event.backends.get()
        for backend in iter_backends:
            errors = backend.dispatch_security_alert(queue_event.event)
            if len(errors):
                for e in errors:
                    print(e.get_message())
            """
            in a real world application we should log errors returned by dispatch_security_alert
            this logger would have to be able to manage concurrent accesses
            """
        q.task_done()


class SqreenAlertDispatchWorker:
    """
    keeps a queue of SecurityAlertQueueEvent
    initializes workers
    """
    q: Queue
    num_fetch_threads: int = 1
    initialized: bool = False

    def __init__(self, num_fetch_threads: int):
        """
        initialize the processing queue and start workers
        :param num_fetch_threads: nb of workers needed
        """
        self.q = Queue()
        if num_fetch_threads is not None:
            self.num_fetch_threads = num_fetch_threads
        self._start()

    def _start(self):
        """initialize workers"""
        if self.initialized:
            raise Exception('dispatch worker already initialized')
        self.initialized = True
        for i in range(self.num_fetch_threads):
            worker = Thread(target=dequeue, args=(i, self.q,))
            worker.setDaemon(True)
            worker.start()

    def push(self, event: SecurityAlertQueueEvent):
        """
        push into the queue
        :param event: alert event to be pushed in the queue
        """
        self.q.put(event)

    def close(self):
        pass

