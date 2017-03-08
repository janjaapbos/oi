import threading
import Queue
import time
import oi


class Worker(threading.Thread):
    """ General purpose worker """

    def __init__(self, program=None, **kwargs):
        super(Worker, self).__init__(**kwargs)
        self.program = program

    def run(self):
        raise Exception('Implement this method in your subclass')


class ServiceWorker(Worker):
    """ Respond to commands from ctl program """

    def __init__(self, service, **kwargs):
        super(ServiceWorker, self).__init__(**kwargs)
        self.service = service

    def run(self):
        self.service.start()


class QueueWorker(Worker):

    def __init__(self, sessions=None, **kwargs):
        self.sessions = sessions
        super(QueueWorker, self).__init__(**kwargs)

    def run(self):
        while self.program.continue_event.wait():
            try:
                ctx = self.sessions.queue.get(block=True)
            except Queue.Empty:
                continue
            self.handle(ctx)
            self.sessions[ctx.session.session_uuid].queue.put(ctx)
            self.sessions.queue.task_done()

    def handle(self, ctx):
        try:
            ctx.result = ctx.func(*ctx.get('args', []), **ctx.get('kwargs', {}))
        except Exception as exception:
            logging.error(
                'Request {} exception {}'.format(ref, exception), exc_info=1)
            ctx.error = str(exception)
