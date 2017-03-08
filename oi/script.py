import os
import re
import sys
import random

from . import core


# =========================================================
# SKELETON FILES
# =========================================================

README = """
myprogram
=========
myprogram and its ctl
"""

Makefile = """
.PHONY: help test

help:
    @echo
    @echo "USAGE: make [target]"
    @echo
    @echo "TARGETS:"
    @echo
    @echo "  install        - install python package"
    @echo "  clean          - cleanup"
    @echo "  test           - run tests"
    @echo "  distribute     - upload to PyPI"
    @echo

install:
    @python setup.py install

test:
    @nosetests test

clean:
    @rm -rf build dist *.egg-info

distribute:
    @python setup.py register -r pypi && python setup.py sdist upload -r pypi
"""


setup = """
#!/usr/bin/env python

try:
    import setuptools
    from setuptools import setup
except ImportError:
    setuptools = None
    from distutils.core import setup


readme_file = 'README.md'
try:
    import pypandoc
    long_description = pypandoc.convert(readme_file, 'rst')
except (ImportError, OSError) as e:
    print('No pypandoc or pandoc: %s' % (e,))
    with open(readme_file) as fh:
        long_description = fh.read()

with open('./myprogram/version.py') as fh:
    for line in fh:
        if line.startswith('VERSION'):
            version = line.split('=')[1].strip().strip("'")

setup(
    name='myprogram',
    version=version,
    packages=['myprogram'],
    author='',
    author_email='',
    url='',
    # license='MIT',
    description='',
    long_description=long_description,
    install_requires=[
        'oi',
    ],
    classifiers=[
        # 'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
    ],

    entry_points={
        'console_scripts': [
            'myprogram = myprogram.myprogram:main',
            'myprogramd = myprogram.myprogramd:main',
            'myprogramctl = myprogram.myprogramctl:main',
            'myprogramsvc = myprogram.myprogramsvc:main',
        ],
    },

)
"""

freeze = """
#!/bin/sh

rm -rf build dist
pyinstaller --hidden-import cffi myprogram/myprogram.py

cp myprogram/config.py dist/myprogram/config.py
cp myprogram/scheduler.py dist/myprogram/scheduler.py

cd dist/myprogram
ln -s myprogram myprogramd
ln -s myprogram myprogramsvc
ln -s myprogram myprogramctl
cd ../../
"""

myprogramd = """
import oi
try:
    import config
except ImportError:
    import myprogram.config as config


def main():
    program = oi.Program('myprogram', config.ctl_url_bind)
    program.add_command('ping', lambda _: 'pong')
    try:
        from scheduler import setup_scheduler, scheduler
    except ImportError: 
        from myprogram.scheduler import setup_scheduler, scheduler
    setup_scheduler(program)
    if hasattr(config, 'register_hook'):
        config.register_hook(
            ctx=dict(
                locals=locals(),
                globals=globals(),
                program=program
            )
        )
    program.run()
    scheduler.shutdown()


if __name__ == '__main__':
    if hasattr(config, 'main_hook'):
        if not config.main_hook(
            ctx=dict(
                locals=locals(),
                globals=globals()
            )
        ):
            main()
    else:
        main()
"""

myprogramctl = """
import oi
try:
    import config
except ImportError:
    import myprogram.config as config


def main():
    ctl = oi.CtlProgram('ctl program', config.ctl_url_connect)
    ctl.run()

if __name__ == '__main__':
    if hasattr(config, 'main_hook'):
        if not config.main_hook(
            ctx=dict(
                locals=locals(),
                globals=globals()
            )
        ):
            main()
    else:
        main()
"""

myprogramsvc = """
import oi
import os
import sys
import logging
from logging.handlers import SysLogHandler
import time
import service
try:
    import config
except ImportError:
    import myprogram.config as config


def stop_function():
    ctl = oi.CtlProgram('ctl program', config.ctl_url_connect)
    ctl.call('stop')
    ctl.client.close()

class Service(service.Service):
    def __init__(self, *args, **kwargs):
        super(Service, self).__init__(*args, **kwargs)
        self.syslog_handler = SysLogHandler(
            address=service.find_syslog(),
            facility=SysLogHandler.LOG_DAEMON
        )
        formatter = logging.Formatter(
            '%(name)s - %(levelname)s - %(message)s')
        self.syslog_handler.setFormatter(formatter)
        logging.getLogger().addHandler(self.syslog_handler)

    def run(self):
        try:
            from scheduler import setup_scheduler, scheduler
        except ImportError: 
            from myprogram.scheduler import setup_scheduler, scheduler
        while not self.got_sigterm():
            logging.info("Starting")
            self.program = oi.Program('myprogram', config.ctl_url_bind)
            self.program.logger = self.logger
            self.program.add_command('ping', lambda _: 'pong')
            def restart():
                logging.warning('Restarting')
                self.program.continue_event.set()
            self.program.restart = restart
            setup_scheduler(self.program)
            if hasattr(config, 'register_hook'):
                config.register_hook(
                    ctx=dict(
                        locals=locals(),
                        globals=globals(),
                        program=self.program
                    )
                )
            self.program.run()
            logging.warning("Stopping")
            scheduler.shutdown()
            if not self.program.continue_event.wait(0.1):
                break
            self.stop()
            os.unlink('/tmp/demo.pid')
            os.execl(sys.executable, sys.argv[0], 'start')
        if self.got_sigterm():
            self.program.stop_function()

def main():
    import sys

    if len(sys.argv) < 2:
        sys.exit('Syntax: %s COMMAND' % sys.argv[0])

    cmd = sys.argv[1]
    sys.argv.remove(cmd)

    service = Service('myprogram', pid_dir='/tmp')

    if cmd == 'start':
        service.start()
    elif cmd == 'stop':
        service.stop()
        stop_function()
    elif cmd == 'restart':
        service.stop()
        stop_function()
        while service.is_running():
            time.sleep(0.1)
        service.start()
    elif cmd == 'status':
        if service.is_running():
            print "Service is running."
        else:
            print "Service is not running."
    else:
        sys.exit('Unknown command "%s".' % cmd)


if __name__ == '__main__':
    if hasattr(config, 'main_hook'):
        if not config.main_hook(
            ctx=dict(
                locals=locals(),
                globals=globals()
            )
        ):
            main()
    else:
        main()
"""

myprogram = """
import oi
import os
import sys
import logging
from logging.handlers import SysLogHandler
import time
import service
try:
    import config
except ImportError:
    import myprogram.config as config


def stop_function():
    ctl = oi.CtlProgram('ctl program', config.ctl_url_connect)
    ctl.call('stop')
    ctl.client.close()

class Service(service.Service):
    def __init__(self, *args, **kwargs):
        super(Service, self).__init__(*args, **kwargs)
        self.syslog_handler = SysLogHandler(
            address=service.find_syslog(),
            facility=SysLogHandler.LOG_DAEMON
        )
        formatter = logging.Formatter(
            '%(name)s - %(levelname)s - %(message)s')
        self.syslog_handler.setFormatter(formatter)
        logging.getLogger().addHandler(self.syslog_handler)

    def run(self):
        try:
            from scheduler import setup_scheduler, scheduler
        except ImportError: 
            from myprogram.scheduler import setup_scheduler, scheduler
        while not self.got_sigterm():
            logging.info("Starting")
            self.program = oi.Program('myprogram', config.ctl_url_bind)
            self.program.logger = self.logger
            self.program.add_command('ping', lambda _: 'pong')
            def restart():
                logging.warning('Restarting')
                self.program.continue_event.set()
            self.program.restart = restart
            setup_scheduler(self.program)
            if hasattr(config, 'register_hook'):
                config.register_hook(
                    ctx=dict(
                        locals=locals(),
                        globals=globals(),
                        program=self.program
                    )
                )
            self.program.run()
            logging.warning("Stopping")
            scheduler.shutdown()
            if not self.program.continue_event.wait(0.1):
                break
            self.stop()
            os.unlink('/tmp/demo.pid')
            os.execl(sys.executable, sys.argv[0], 'start')
        if self.got_sigterm():
            self.program.stop_function()

def main_ctl():
    ctl = oi.CtlProgram('ctl program', config.ctl_url_connect)
    ctl.run()

def main_d():
    program = oi.Program('myprogram', config.ctl_url_bind)
    program.add_command('ping', lambda _: 'pong')
    try:
        from scheduler import setup_scheduler, scheduler
    except ImportError: 
        from myprogram.scheduler import setup_scheduler, scheduler
    setup_scheduler(program)
    if hasattr(config, 'register_hook'):
        config.register_hook(
            ctx=dict(
                locals=locals(),
                globals=globals(),
                program=program
            )
        )
    program.run()
    scheduler.shutdown()

def main_svc():
    import sys

    if len(sys.argv) < 2:
        sys.exit('Syntax: %s COMMAND' % sys.argv[0])

    cmd = sys.argv[1]
    sys.argv.remove(cmd)

    service = Service('myprogram', pid_dir='/tmp')

    if cmd == 'start':
        service.start()
    elif cmd == 'stop':
        service.stop()
        stop_function()
    elif cmd == 'restart':
        service.stop()
        stop_function()
        while service.is_running():
            time.sleep(0.1)
        service.start()
    elif cmd == 'status':
        if service.is_running():
            print "Service is running."
        else:
            print "Service is not running."
    else:
        sys.exit('Unknown command "%s".' % cmd)

def main():
    prog_name = sys.argv[0].lower()
    if prog_name.endswith('.exe'):
        prog_name = prog_name[:-4]
    if prog_name.endswith('svc'):
        main_svc()
    elif prog_name.endswith('d'):
        main_d()
    else:
        main_ctl()

if __name__ == '__main__':
    if hasattr(config, 'main_hook'):
        if not config.main_hook(
            ctx=dict(
                locals=locals(),
                globals=globals()
            )
        ):
            main()
    else:
        main()
"""

config = '''
"""
If this config file is placed in the same directory as the
frozen binary, is will be loaded instead of the frozen config.
"""

ctl_url_bind = 'ipc:///tmp/oi-random_string.sock'
ctl_url_connect = 'ipc:///tmp/oi-random_string.sock'
# ctl_url_bind = 'ws://*:5558'
# ctl_url_connect = 'ws://localhost:5558'

import logging

def main_hook(ctx=None):
    """
    Custom hook to be executed. A return value other than None
    will stop further execution.
    """
    # logging.basicConfig(level=logging.DEBUG)
    # logging.debug('config.main_hook')

def register_hook(ctx=None):
    """
    Custom hook to extend and register commands with the program.
    ctx is a dict with locals, globals and program object
    """
    # logging.debug('config.register_hook')
    ctx['program'].add_command('hello', lambda _: 'world')
'''

scheduler = """
from pytz import utc
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
import logging

# Needed for pyinstaller
from apscheduler.triggers.interval import IntervalTrigger  # NOQA

jobstores = {
    'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')
}
executors = {
    'default': ThreadPoolExecutor(20),
    'processpool': ProcessPoolExecutor(5)
}
job_defaults = {
    'coalesce': False,
    'max_instances': 3
}
scheduler = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults, timezone=utc)

def test_func():
    pass

def test(program):
    job_id = '2b40852613b348b5b595ab07fe875837'
    job = scheduler.get_job(job_id)
    if not job:
        job = scheduler.add_job(test_func, IntervalTrigger(seconds=10), id=job_id, replace_existing=True)
    return job

#def test(program):
#    job = scheduler.add_job(test_func, IntervalTrigger(seconds=10))
#    return job

def get_jobs():
    return '\\n'.join([job.id for job in scheduler.get_jobs()])

def get_job(jobid):
    return str(scheduler.get_job(jobid))

def remove_job(jobid):
    return str(scheduler.remove_job(jobid))

def setup_scheduler(program):
    def my_listener(event):
        if event.exception:
            logging.error('Job crashed: ' + str(event))
        else:
            logging.info('Job executed: ' + str(event))

    scheduler.add_listener(
        my_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR
    )
    program.add_command('get_jobs', get_jobs)
    program.add_command('get_job', get_job)
    program.add_command('remove_job', remove_job)
    scheduler.start()
    logging.info('Started scheduler')
    #test(program)
    #logging.info('Scheduled test job')


"""

# =========================================================
# GENERATE SKELETON LOGIC
# =========================================================

def init_new_project(program):

    if os.listdir('.') != []:
        print('Directory not empty. Abort!')
        sys.exit(1)

    # ---

    name = os.path.basename(os.getcwd())

    src_dir = './{}'.format(name)
    os.mkdir(src_dir)

    # Add readme file
    with open('README.md', 'w') as fh:
        fh.write(README.replace('myprogram', name).lstrip())

    # Add setup script
    with open('setup.py', 'w') as fh:
        fh.write(setup.replace('myprogram', name).lstrip())

    # Add Makefile
    with open('Makefile', 'w') as fh:
        data = Makefile.replace('myprogram', name).lstrip()
        data = re.sub(r'    @', r'\t@', data)
        fh.write(data)

    # Add freeze script
    with open('freeze.sh', 'w') as fh:
        fh.write(freeze.replace('myprogram', name).lstrip())
    os.chmod('freeze.sh', 0o775)

    # Add py files
    files = [
        ('myprogram.py', myprogram),
        ('myprogramd.py', myprogramd),
        ('myprogramsvc.py', myprogramsvc),
        ('myprogramctl.py', myprogramctl),
        ('config.py', config),
        ('scheduler.py', scheduler)]

    random_string = ''.join(random.sample([chr(i) for i in range(97, 123)], 10))

    for filename, var in files:
        filename = filename.replace('myprogram', name)
        with open(os.path.join(src_dir, filename), 'w') as fh:
            var = var.replace('myprogram', name).lstrip()
            var = var.replace('random_string', random_string)
            fh.write(var)

    # Add version file
    with open(os.path.join(src_dir, 'version.py'), 'w') as fh:
        fh.write("VERSION = '0.0.1\n'")

    # Add __init__ file
    with open(os.path.join(src_dir, '__init__.py'), 'w') as fh:
        pass


def main():
    program = core.CtlProgram(
        'init a new oi program in current empty directory', None)
    program.add_command('init', init_new_project)
    program.run(loop=False)


if __name__ == '__main__':
    main()
