import sys
import os
import shutil
import argparse
import threading
import Queue
import readline
import logging
import time
import json

from colorama import Fore
from nanoservice import Responder, Requester, AuthenticateError
try:
    from nanoservice import nanomsg, nnpy
except ImportError:
    import nanomsg
    nnpy = None

from . import version
from . import worker
from . import compat
from . import util

import uuid
import re
re_uuid4 = re.compile('^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z', re.I)

lock = threading.Lock()


class AuthorisationError(Exception):
    """Generic Authorisation error"""


def assert_valid_uuid(uuid):
    match = re_uuid4.match(uuid)
    if not bool(match):
        raise ValueError('Invalid uuid format: ' + uuid)
    return True

class State(dict):
    """ A dot access dictionary """

    def __init__(self, *args, **kwargs):
        super(State, self).__init__(self, *args, **kwargs)

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key, value):
        lock.acquire()
        self[key] = value
        lock.release()


class AuthToken(State):
    """ AuthToken dict """

    def __init__(self, token, info=None):
        assert_valid_uuid(token)
        super(AuthToken, self).__init__()
        self.token = token
        self.info = info


class Session(State):
    """ Session dict """

    def __init__(self, session_uuid):
        assert_valid_uuid(session_uuid)
        super(Session, self).__init__()
        self.session_uuid = session_uuid
        self.auth_tokens = State()
        self.tags = State()
        self.caps = State()
        self.queue = Queue.Queue()
        self.timestamp = time.time()

    def auth_token_add(self, info=None, token=None):
        if token is None:
            token = str(uuid.uuid4())
        self.auth_tokens[token] = AuthToken(
            token, info=info)
        return token

    def auth_token_del(self, token):
        del self.auth_tokens[token]

    def auth_token_valid(self, token):
        if token not in self.auth_tokens:
            raise ValueError('Invalid token')


class Sessions(object):
    """ Sessions dict """

    def __init__(self, program, purge_interval=5, expire=15):
        self.purge_interval = purge_interval
        self.expire = expire
        self.program = program
        self.sessions = State()
        self.tags = State()
        self.caps = State()
        self.queue = Queue.Queue()
        self.purge_sessions()

    def purge_sessions(self):
        if not self.program.continue_event.wait(1):
            return
        threading.Timer(self.purge_interval, self.purge_sessions).start()
        keys = self.sessions.keys()
        for session_uuid in keys[:]:
            if session_uuid == self.program.session_uuid:
                continue
            session = self.sessions.get(session_uuid)
            if not session:
                continue
            try:
                if time.time() - session.timestamp > self.expire:
                    logging.debug('Purging session {} with timestamp {}'.format(
                        session_uuid, session.timestamp))
                    self._session_del(session)
            except Exception as exception:
                logging.error(
                    'Purge {} exception {}'.format(session, exception), exc_info=1)
                error = str(exception)

    """ Not to be exposed directly, only to be used in functions """
    def _cmd(self, cmd, ctx, *args):
        func = getattr(ctx.session, cmd)
        return func(*args)

    def enqueue_ctx(self, ctx):
        ctx.queued = True
        self.queue.put(ctx)

    def login_validate(self, username, password):
        logging.debug('login_validate username {}'.format(username))
        if not username:
            raise AuthenticateError('Invalid credentials')
        if username == self.program.username:
            if password == self.program.password:
                return
        raise AuthenticateError('Invalid credentials')

    def login(self, ctx, session_uuid, username, password):
        self.login_validate(username, password)
        token = self.session_add(None, session_uuid)
        session = self.sessions[session_uuid]
        if username == self.program.username:
            self._cap_set(session, 'system.file', '/')
            self._tag_set(session, 'domain', 'system')
        else:
            self._tag_set(session, 'domain', 'client')
        return token

    def logout(self, ctx):
        return 'logged out'

    def session_add(self, ctx, session_uuid, auth_token=None):
        if not isinstance(session_uuid, basestring) and not session_uuid:
            raise ValueError('Session uuid must be a uuidV4 string')
        assert_valid_uuid(session_uuid)
        if session_uuid in self.sessions:
            raise ValueError('Session exists: ' + session_uuid)
        self.sessions[session_uuid] = Session(session_uuid)
        return self.sessions[session_uuid].auth_token_add(
            'Created at new session',
            auth_token
        )

    def _session_del(self, session):
        session['deleted'] = True
        for name in session.tags.keys()[:]:
            self._tag_del(session, name)
        for name in session.caps.keys()[:]:
            self._cap_del(session, name)
        del self.sessions[session['session_uuid']]

    def session_del(self, ctx, session_uuid=None, auth_token=None):
        if not ctx.session and not session_uuid:
            raise ValueError("No session provided")
        if session_uuid and auth_token:
            delete_session = self.session_get(ctx, session_uuid, auth_token)
        else:
            delete_session = ctx.session
        self._session_del(delete_session)

    def session_get(self, ctx, session_uuid=None, auth_token=None):
        if not ctx.session and not session_uuid:
            raise ValueError("No session provided")
        if session_uuid and auth_token:
            assert_valid_uuid(session_uuid)
            if not session_uuid in self.sessions:
                raise AuthenticateError('Invalid credentials')
            self.sessions[session_uuid].auth_token_valid(auth_token)
            self.sessions[session_uuid].timestamp = time.time()
            return self.sessions[session_uuid]
        return ctx.session

    def auth_token_add(self, *args):
        return self._cmd('auth_token_add', *args)

    def auth_token_del(self, *args):
        return self._cmd('auth_token_del', *args)

    def tag_set_validate(ctx, tag_session, tag_name, tag_value):
        if tag_name in [
            'domain', 'system'
        ] or tag_name.startswith('system.'):
            if not ctx.session.tags['domain'] == 'system':
                raise AuthorisationError('tag privilige')
        allowed_prefix = 'client.%s' % (ctx.session_uuid)
        if not tag_name.startswith(allowed_prefix):
            raise AuthorisationError('Tag should start with: ' + allowed_prefix)


    def tag_set(self, ctx, session_uuid, tag_name, tag_value):
        assert_valid_uuid(session_uuid)
        tag_session = self.sessions[session_uuid]
        self.tag_set_validate(ctx, tag_session, tag_name, tag_value)
        if tag_name not in self.tags:
            self.tags[tag_name] = State()
        self.tags[tag_name][tag_session.session_uuid] = value
        tag_session.tags[tag_name] = tag_value

    def _tag_set(self, session, tag_name, tag_value):
        if tag_name not in self.tags:
            self.tags[tag_name] = State()
        self.tags[tag_name][session.session_uuid] = tag_value
        session.tags[tag_name] = tag_value

    def tag_del(self, ctx, session_uuid, tag_name):
        assert_valid_uuid(session_uuid)
        tag_session = self.sessions[session_uuid]
        self.tag_set_validate(ctx, tag_session, tag_name)
        try:
            del ctx.session.tags[tag_name]
        except IndexError:
            pass
        try:
            del self.tags[tag_name][ctx.session.session_uuid]
        except IndexError:
            pass

    def _tag_del(self, session, tag_name):
        try:
            del session.tags[tag_name]
        except IndexError:
            pass
        try:
            del self.tags[tag_name][session.session_uuid]
        except IndexError:
            pass

    def tag_get(self, ctx, tag_name=None):
        if tag_name:
            if tag_name in ctx.session.tags:
                return {tag_name: session.tags[tag_name]}
            return None
        return ctx.session.tags

    def cap_set_validate(ctx, cap_session, cap_name, cap_value=None):
        if cap_name in [
            'domain', 'system'
        ] or cap_name.startswith('system.'):
            if not ctx.session.caps['domain'] == 'system':
                raise AuthorisationError('cap privilige')
        allowed_prefix = 'client.%s' % (ctx.session_uuid)
        if not cap_name.startswith(allowed_prefix):
            raise AuthorisationError('Tag should start with: ' + allowed_prefix)

    def cap_set(self, ctx, session_uuid, cap_name, cap_value):
        assert_valid_uuid(session_uuid)
        cap_session = self.sessions[session_uuid]
        self.cap_set_validate(ctx, cap_session, cap_name, cap_value)
        if cap_name not in self.caps:
            self.caps[cap_name] = State()
        self.caps[cap_name][cap_session.session_uuid] = value
        cap_session.caps[cap_name] = cap_value

    def _cap_set(self, session, cap_name, cap_value):
        if cap_name not in self.caps:
            self.caps[cap_name] = State()
        self.caps[cap_name][session.session_uuid] = cap_value
        session.caps[cap_name] = cap_value

    def cap_del(self, ctx, session_uuid, cap_name):
        assert_valid_uuid(session_uuid)
        cap_session = self.sessions[session_uuid]
        self.cap_set_validate(ctx, cap_session, cap_name)
        try:
            del cap_session.caps[cap_name]
        except IndexError:
            pass
        try:
            del self.caps[cap_name][cap_session.session_uuid]
        except IndexError:
            pass

    def _cap_del(self, session, cap_name):
        try:
            del session.caps[cap_name]
        except IndexError:
            pass
        try:
            del self.caps[cap_name][session.session_uuid]
        except IndexError:
            pass

    def cap_get(self, session, cap_name=None):
        if cap_name:
            if cap_name in session.caps:
                return {cap_name: session.caps[cap_name]}
            return None
        return session.caps


class FileOperation(object):
    """Class for common file functions"""

    def __init__(self, restrict_dir):
        self.restrict_dir = restrict_dir

    def assert_valid_authorisation(self, ctx):
        if ctx.session.tags.domain == 'client':
            if not 'system.file' in ctx.session.caps:
                raise AuthorisationError('cap system.file required')
            self.assert_valid_path(ctx.session.caps['system.file'])
        elif ctx.session.tags.domain != 'system':
            raise AuthorisationError('Invalid tag or cap')

    def assert_valid_path(self, path, inside=False, follow_symlinks=True):
        if follow_symlinks:
            if not os.path.realpath(path).startswith(self.restrict_dir):
                raise Exception(
                    'Path {} outside restrict_dir {}'.format(
                        path, self.restrict_dir))
            if inside and os.path.realpath(path) == self.restrict_dir:
                raise Exception(
                    'Path {} same as restrict_dir {}'.format(
                        path, self.restrict_dir))
            return
        if not os.path.abspath(path).startswith(self.restrict_dir):
            raise Exception('Path {} outside restrict_dir {}'.format(
                path, self.restrict_dir))
        if inside and os.path.abspath(path) == self.restrict_dir:
            raise Exception('Path {} same as restrict_dir {}'.format(
                path, self.restrict_dir))

    def make_archive(self, ctx, base_name, format, root_dir, base_dir,
                     dry_run=False, owner=None, group=None):
        self.assert_valid_authorisation(ctx)
        for path in [base_name, root_dir, base_dir]:
            if not self.assert_valid_path(root_dir):
                raise Exception('Path {} outside restrict_dir {}'.format(
                    path, self.restrict_dir))
        shutil.make_archive(base_name=base_name, format=format,
            root_dir=root_dir, base_dir=base_dir,
            dry_run=dry_run, owner=owner, group=group)
        return "Archive created"

    def get_archive_formats(self, ctx):
        return shutil.get_archive_formats()

    def file_get(self, ctx, path, offset=0, count=1000000):
        offset = int(offset)
        count = int(count)
        self.assert_valid_authorisation(ctx)
        self.assert_valid_path(path)
        ctx.content_type = 'application/octet-stream'
        with open(path, 'rb') as fp:
            fp.seek(int(offset))
            content = fp.read(int(count))
        total_size = os.path.getsize(path)
        done = offset + count
        remaining = total_size - done
        if remaining > 0:
            next_offset = done
        else:
            next_offset = 0
        result = dict(
            path=path,
            total_size=total_size,
            offset=offset,
            count=count,
            next_offset=next_offset,
            content=content,
            content_type=ctx.content_type
        )
        return result

    def file_get_size(self, ctx, path):
        self.assert_valid_authorisation(ctx)
        self.assert_valid_path(path)
        return os.path.getsize(path)

    def file_put(self, ctx, path, blob, offset=0):
        offset = int(offset)
        mode = 'ab'
        if offset == 0:
            mode = 'wb'
        self.assert_valid_authorisation(ctx)
        self.assert_valid_path(path, inside=True)
        with open(path, mode) as fp:
            fp.seek(int(offset))
            fp.write(blob)
        return


class BaseProgram(object):
    """ Subclass this """

    session_uuid = None

    def __init__(self, description, address=None, state=None, workers=None,
                 args=None, session_uuid=None, auth_token=None,
                 username=None, password=None
        ):
        logging.basicConfig(level=logging.WARNING)
        self.description = description
        self.parser = self.new_parser()
        if args is None:
            args, unknown = self.parser.parse_known_args()
        self.config = compat.configparser.ConfigParser({
            'address': address,
        })
        # Read configuration file if any
        if args.config is not None:
            filepath = args.config
            self.config.read(filepath)
            address = self.config.get('default', 'address')

        self.address = address
        self.state = state or State()
        self.workers = workers or []
        self.registered = {}  # registered commands

        if session_uuid is None:
            session_uuid = args.session_uuid or str(uuid.uuid4())
        if session_uuid:
            assert_valid_uuid(session_uuid)
        self.session_uuid = session_uuid
        # if auth_token is None:
        #     auth_token = args.auth_token or str(uuid.uuid4())
        # if auth_token != 'new':
        #     assert_valid_uuid(auth_token)
        #     self.auth_token = auth_token
        if auth_token is None:
            auth_token = args.auth_token
        if auth_token:
            assert_valid_uuid(auth_token)
            self.auth_token = auth_token
        else:
            self.auth_token = None

        if username is None:
            username = args.username
        self.username = username
        if password is None:
            password = args.password
        self.password = password

    def new_parser(self):
        """ Create a command line argument parser

        Add a few default flags, such as --version
        for displaying the program version when invoked """

        parser = argparse.ArgumentParser(description=self.description)
        parser.add_argument(
            '--version', help='show version and exit',
            default=False, action='store_true')
        parser.add_argument(
            '--debug', help='enable debugging',
            default=False, action='store_true')
        # Add the flag for parsing configuration file
        parser.add_argument(
            '--config', help='configuration file to use', nargs='?')
        parser.add_argument(
            '--session_uuid', help='Session ID (uuidv4) to use', nargs='?')
        parser.add_argument(
            '--auth_token', help='Auth token (uuidv4) to use', nargs='?')
        parser.add_argument(
            '--username', help='login username', nargs='?')
        parser.add_argument(
            '--password', help='login password', nargs='?')
        return parser

    def add_command(self, command, function, description=None):
        """ Register a new function with a the name `command` and
        `description` (which will be shown then help is invoked). """

        self.registered[command] = {
            'function': function, 'description': description
        }

    def run(self, args=None):
        """ Parse command line arguments if necessary then run program.
        By default this method will just take of the --version flag.

        The logic for other flags should be handled by your subclass """

        args = args or self.parser.parse_args()

        logging.info('run args: ' + str(args))
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        if args.version:
            print(version.VERSION)
            sys.exit(0)


class Program(BaseProgram):
    """ Long running program with a nanoservice endpoint.

    `service` - nanoservice Responder object
    `config` - the configuration parsed from --config <filepath> """

    def __init__(self, description, address):
        super(Program, self).__init__(description, address)

        self.continue_event = threading.Event()
        self.continue_event.set()
        self.service = Responder(self.address)
        self.service.continue_event = self.continue_event
        self.service.stop_cleanup = self.stop_cleanup
        self.restart_requested = False

        if self.service is None:
            return

        self.cli_sessions = Sessions(self)
        self.svc_sessions = Sessions(self)
        self.service.get_cli_session = self.cli_sessions.session_get
        if not self.auth_token:
            self.auth_token = str(uuid.uuid4())
        self.cli_sessions.session_add(None, self.session_uuid, self.auth_token)
        self.session = self.cli_sessions.sessions[self.session_uuid]
        self.cli_sessions._tag_set(self.session, 'domain', 'system')

        # Add default service worker, which will respond to ctl commands
        # Other workers will perform other kind of work, such as
        # fetching resources from the web, etc
        self.workers.append(worker.ServiceWorker(self.service))

        # Add default commands
        self.add_command('ping', lambda _: 'pong')
        self.add_command('help', self.help_function)
        self.add_command('stop', self.stop_function)
        self.add_command('restart', self.restart_function, 'Restart service')
        self.add_command('login', self.cli_sessions.login,
                         'Login with session_uuid, username and password '
                         'to obtain an auth token for the new session_uuid')
        self.add_command('logout', self.cli_sessions.logout)
        self.add_command('cli_session_add', self.cli_sessions.session_add,
                         'Add session for client with provided uuid')
        self.add_command('cli_session_del', self.cli_sessions.session_del)
        self.add_command('cli_session_auth_token_add', self.cli_sessions.auth_token_add)
        self.add_command('cli_session_auth_token_del', self.cli_sessions.auth_token_del)
        self.add_command('cli_session_tag_set', self.cli_sessions.tag_set)
        self.add_command('cli_session_tag_del', self.cli_sessions.tag_del)
        self.add_command('cli_session_tag_get', self.cli_sessions.tag_get)
        self.add_command('cli_session_cap_set', self.cli_sessions.cap_set)
        self.add_command('cli_session_cap_del', self.cli_sessions.cap_del)
        self.add_command('cli_session_cap_get', self.cli_sessions.cap_get)
        # self.add_command('remote', self.remote_func)
        self.add_command('queue_hello', self.queue_hello_function)
        self.add_command('noop', self.noop_function)
        self.file_operation = FileOperation('/')
        self.add_command('file_make_archive', self.file_operation.make_archive,
                        shutil.make_archive.__doc__)
        self.add_command('file_get_archive_formats',
                         self.file_operation.get_archive_formats)
        self.add_command('file_get', self.file_operation.file_get),
        self.add_command('file_get_size', self.file_operation.file_get_size),
        self.add_command('file_put', self.file_operation.file_put),
        self.create_worker_pool()

    def stop_cleanup(self):
        for w in self.workers:
            self.cli_sessions.queue.put('stop')

    def create_worker_pool(self):
        for i in range(10):
            self.workers.append(worker.QueueWorker(program=self, sessions=self.cli_sessions))

    def queue_hello_function(self, ctx, who):
        import time
        def hello(who, other='test'):
            logging.debug('start hello for {} from {}'.format(
                ctx.session.session_uuid, other))
            time.sleep(5)
            logging.debug('finished hello for ' + ctx.session.session_uuid)
            return 'hello {} from {}'.format(
                ctx.session.session_uuid, other)
        ctx.func = hello
        ctx.args = [who]
        ctx.kwargs = dict(other='test3')
        self.cli_sessions.enqueue_ctx(ctx)

    def noop_function(self, ctx):
        pass

    def help_function(self, ctx, command=None):
        """ Show help for all available commands or just a single one """
        if command:
            return self.registered[command].get(
                'description', 'No help available'
            )
        return ', '.join(sorted(self.registered))

    def ping_function(self, ctx):
        return 'pong'

    def stop_function(self, ctx):
        if ctx.session.tags['domain'] != 'system':
            raise AuthorisationError('tag domain:system required')
        self.continue_event.clear()

    def restart_function(self, ctx):
        if ctx.session.tags['domain'] != 'system':
            raise AuthorisationError('tag domain:system required')
        self.restart_requested = True
        self.stop_function(ctx)

    def restart(self):
        os.execv(sys.argv[0], sys.argv)

    def add_command(self, command, function, description=None):
        """ Register a new function for command """
        super(Program, self).add_command(command, function, description)
        self.service.register(command, function)

    def run(self, args=None):
        """ Parse comand line arguments/flags and run program """

        args = args or self.parser.parse_args()
        super(Program, self).run(args)

        # Start workers then wait until they finish work
        [w.start() for w in self.workers]

        while self.continue_event.wait(1):
           [w.join() for w in self.workers]

        if self.restart_requested:
            self.restart()


class ClientWrapper(object):
    """ An wrapper over nanoservice.Requester to deal with one or multiple
    clients in a similar fasion """

    def __init__(self, address, timeout, session_uuid=None, auth_token=None):
        self.c = self.create_client(address, timeout, session_uuid, auth_token)

    def create_client(self, addr, timeout, session_uuid, auth_token):
        """ Create client(s) based on addr """

        def make(addr):
            c = Requester(addr, session_uuid=session_uuid, auth_token=auth_token)
            if nanomsg:
                c.socket._set_recv_timeout(timeout)
            else:
                c.socket.setsockopt(nnpy.SOL_SOCKET, nnpy.RCVTIMEO, timeout)
                c.socket.setsockopt(nnpy.SOL_SOCKET, nnpy.IPV4ONLY, 0)
            return c

        if ',' in addr:
            addrs = addr.split(',')
            addrs = [a.strip() for a in addrs]
            return {a: make(a) for a in addrs}
        return make(addr)

    def _call_single(self, client, command, *args):
        """ Call single """
        try:
            return client.call(command, *args)
        except Exception as e:
            return None, str(e)

    def _call_multi(self, clients, command, *args):
        """ Call multi """
        responses, errors = {}, {}
        for addr, client in clients.items():
            res, err = self._call_single(client, command, *args)
            responses[addr] = res
            errors[addr] = err
        return responses, errors

    def call(self, command, *args):
        """ Call remote service(s) """
        if isinstance(self.c, dict):
            return self._call_multi(self.c, command, *args)
        return self._call_single(self.c, command, *args)

    def is_multi(self):
        """ Does this object include multiple clients """
        return isinstance(self.c, dict)

    def close(self):
        """ Close socket(s) """
        if isinstance(self.c, dict):
            for client in self.c.values():
                client.sock.close()
            return
        self.c.socket.close()


class Response(object):
    """ A local or remote response for a command """

    def __init__(self, kind, rep, multi=False):
        super(Response, self).__init__()
        self.kind = kind
        self.rep = rep
        self.multi = multi

    def _show(self, res, err, prefix='', colored=False):
        """ Show result or error """

        if self.kind is 'local':
            what = res if not err else err
            print(what)
            return

        if self.kind is 'remote':
            if colored:
                red, green, reset = Fore.RED, Fore.GREEN, Fore.RESET
            else:
                red = green = reset = ''
            if err:
                what = prefix + red + 'remote err: {}'.format(err) + reset
            else:
                what = prefix + green + str(res) + reset
            print(what)

    def show(self, pargs=None, count=1):
        if pargs and pargs.save_file:
            fname = pargs.save_file
            if count > 1:
                mode = 'ab'
            else:
                mode = 'wb'
        elif pargs and pargs.append_file:
            fname = pargs.append_file
            mode = 'ab'
        else:
            fname = ''
        if not self.rep:
            res = err = None
        else:
            res = self.rep.get('result')
            err = self.rep.get('error')
        if res and fname:
            with open(fname, mode) as fpout:
                try:
                    content_type = self.rep.get('content_type', 'application/text')
                except AttributeError:
                    content_type = ''
                if content_type == 'application/octet-stream':
                    fpout.write(res['content'])
                elif content_type == 'application/json':
                    fpout.write(json.dumps(res['content']))
                elif content_type == 'application/text':
                    fpout.write(res['content'])
                else:
                    fpout.write(res)
            if res['next_offset'] > 0:
                print 'remaining bytes:', res['total_size'] - res['next_offset']
                print 'next offset:', res['next_offset']
            else:
                print 'saved file:', fname
            return
        if self.multi:
            for addr in res:
                self._show(
                    res[addr], err[addr],
                    prefix='- {}: '.format(addr), colored=True
                )
            return
        self._show(res, err)


class CtlProgram(BaseProgram):
    """ The Ctl program

    Note:

        When a CtlProgram accepts a command it will make a request
        to the remote service with that command and any args extracted.

        When we add commands via `add_command` method, then those
        commands will be executed by our registered function; they will
        be not dispatched to the remote service. This is helpful, because
        it allows us to register certain local commands, such as `quit`, etc

     """

    def __init__(self, description, address, timeout=3000, session_uuid=None,
                 auth_token=None):
        super(CtlProgram, self).__init__(description, address,
                                         session_uuid=session_uuid,
                                         auth_token=auth_token)
        if self.address:
            self.client = ClientWrapper(self.address, timeout, self.session_uuid, self.auth_token)

        # Add default commands
        self.add_command('quit', lambda p: sys.exit(0), 'quit ctl')
        self.add_command('cli_file_get', self.cli_file_get)
        self.add_command('cli_file_put', self.cli_file_put)

    def new_parser(self):
        parser = super(CtlProgram, self).new_parser()
        # Add command argument
        parser.add_argument(
            'command', help='command name to execute', nargs='*',
            metavar='command')
        parser.add_argument(
            '--save_file', help='Save output to file', nargs='?')
        parser.add_argument(
            '--append_file', help='Append output to file', nargs='?')
        return parser

    def call(self, command, *args):
        """ Execute local OR remote command and show response """

        if not command:
            return

        rep = {}

        # Look for local methods first
        try:
            rep = self.registered[command]['function'](self, *args)
            return [Response('local', rep, None)]

        # Method not found, try remote
        except KeyError:

            # Execute remote command
            resp = self.client.call(command, *args)
            if isinstance(resp, list):
                responses = []
                for rep in resp:
                    responses.append(
                        Response('remote', rep, self.client.is_multi())
                    )
                return responses
            else:
                return [Response('remote', resp, self.client.is_multi())]

        # Local exception
        except Exception as e:
            rep['error'] = str(e)
            return [Response('local', rep)]

    def parse_input(self, text):
        """ Parse ctl user input. Double quotes are used
        to group together multi words arguments. """

        parts = util.split(text)
        command = parts[0] if text and parts else None
        command = command.lower() if command else None
        args = parts[1:] if len(parts) > 1 else []

        return (command, args)

    def loop(self):
        """ Enter loop, read user input then run command. Repeat """

        while True:
            text = compat.input('ctl > ')
            command, args = self.parse_input(text)
            if not command:
                continue
            for response in self.call(command, *args):
                response.show()

    def login(self):
        response = self.call('login', self.session_uuid, self.username, self.password)
        if len(response) > 1:
            raise ValueError('Got more than one response')
        if response[0].rep.get('error'):
            raise AuthenticateError(
                'Login error {}'.format(response[0].rep.get('error')))
        self.auth_token = self.client.auth_token = self.client.c.auth_token = response[0].rep.get('result')

    def save_content(self):
        pass

    def cli_file_get(self, prog, src_path, dst_path, offset=0, count=1000000):
        with open(dst_path, 'wb') as fpout:
            while True:
                for response in self.call('file_get', src_path, offset, count):
                    rep = response.rep
                    res = rep.get('result')
                    err = rep.get('error')
                    if err:
                        return response
                    assert res['path'] == src_path
                    fpout.write(res['content'])
                if res['next_offset'] > 0:
                    logging.debug(
                        'remaining bytes:', res['total_size'] - res['next_offset'])
                    logging.debug('next offset:', res['next_offset'])
                    offset = res['next_offset']
                else:
                    break
        return dict(result='saved file: {}'.format(dst_path))

    def cli_file_put(self, prog, src_path, dst_path):
        offset = 0
        count = 1000000
        with open(src_path, 'rb') as fpin:
            while True:
                blob = fpin.read(count)
                if not blob:
                    break
                response = self.call('file_put', dst_path, blob, offset)[0]
                res = response.rep.get('result')
                err = response.rep.get('error')
                if err:
                    return response.rep
                offset += count
        return dict(result='copied file: {}'.format(dst_path))

    def run(self, args=None, loop=True):

        pargs = self.parser.parse_args()
        super(CtlProgram, self).run(pargs)

        # Execute a single command then exit
        if pargs.command:
            # command will come as a list (zero or more elements)
            # so, extract the first element as the command name
            # and the rest will all be positional arguments
            command = pargs.command[0]
            args = pargs.command[1:] if len(pargs.command) > 1 else []
            if not self.auth_token and self.username and self.password:
                if command != 'login':
                    self.login()

            response = self.call(command, *args)
            if isinstance(response, list):
                count = 0
                for resp in response:
                    count += 1
                    if resp:
                        resp.show(pargs=pargs, count=count)
            else:
                if response:
                    response.show(pargs=pargs, count=1)
            sys.exit(0)

        if not self.auth_token and self.username and self.password:
            self.login()

        # Enter command loop
        if loop:
            self.loop()
