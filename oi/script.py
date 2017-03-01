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
            'myprogramd = myprogram.myprogramd:main',
            'myprogramctl = myprogram.myprogramctl:main',
            'myprogramsvc = myprogram.myprogramsvc:main',
        ],
    },

)
"""

myprogramd = """
import oi
from scheduler import setup_scheduler, scheduler
import logging
from .config import ctl_url


def main():
    program = oi.Program('myprogram', ctl_url)
    program.add_command('ping', lambda: 'pong')
    program.add_command('state', lambda: program.state)
    setup_scheduler(program)
    program.run()
    scheduler.shutdown()

if __name__ == '__main__':
    main()
"""

myprogramctl = """
import oi
from .config import ctl_url


def main():
    ctl = oi.CtlProgram('ctl program', ctl_url)
    ctl.run()

if __name__ == '__main__':
    main()
"""

myprogramsvc = """
import oi
import sys
import logging
from logging.handlers import SysLogHandler
import time
import service
from .config import ctl_url


def stop_function():
    ctl = oi.CtlProgram('ctl program', ctl_url)
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
        from scheduler import setup_scheduler, scheduler
        while not self.got_sigterm():
            logging.info("Starting")
            self.program = oi.Program('myprogram', ctl_url)
            self.program.logger = self.logger
            self.program.add_command('ping', lambda: 'pong')
            self.program.add_command('state', lambda: self.program.state)
            setup_scheduler(self.program)
            self.program.run()
            scheduler.shutdown()
            #self.logger.info("Stopping")
            logging.info("Stopping")
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
    main()
"""

config = """
ctl_url = 'ipc:///tmp/oi-random_string.sock'
"""

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
    #program.logger.info('Job 1 ' + str(job))
    logging.info('Job 1 ' + str(job))
    if not job:
        job = scheduler.add_job(test_func, IntervalTrigger(seconds=10), id=job_id, replace_existing=True)
        #program.logger.info('Job 2 ' + str(job))
        logging.info('Job 2 ' + str(job))
    return job

def test(program):
    job = scheduler.add_job(test_func, IntervalTrigger(seconds=10))
    return job

def get_jobs():
    return '\\n'.join([job.id for job in scheduler.get_jobs()])

def get_job(jobid):
    return str(scheduler.get_job(jobid))

def remove_job(jobid):
    return str(scheduler.remove_job(jobid))

def dir_scheduler():
    return dir(scheduler)

def setup_scheduler(program):
    def my_listener(event):
        if event.exception:
            print('The job crashed :(')
        else:
            print('The job worked :)')

    scheduler.add_listener(
        my_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR
    )
    program.add_command('get_jobs', get_jobs)
    program.add_command('get_job', get_job)
    program.add_command('remove_job', remove_job)
    scheduler.start()
    #program.logger.info('Started scheduler')
    logging.info('Started scheduler')
    test(program)
    #program.logger.info('Scheduled test job')
    logging.info('Scheduled test job')


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

    # Add py files
    files = [
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
