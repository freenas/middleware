#
# Copyright 2016 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import argparse
import enum
import errno
import os
import sys
import logging
import select
import time
import uuid
import signal
import pwd
import grp
import bsd
import contextlib
from threading import Thread, Condition, Timer, RLock
from freenas.dispatcher.rpc import RpcContext, RpcService, RpcException, generator, get_sender
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.server import Server
from freenas.utils import configure_logging, first_or_default, query as q
from freenas.utils.trace_logger import TRACE


DEFAULT_SOCKET_ADDRESS = 'unix:///var/run/serviced.sock'
BOOTSTRAP_JOB = ['/usr/local/sbin/servicectl', 'bootstrap']
MAX_EVENTS = 16
SHUTDOWN_TIMEOUT = 60
BASE_ENV = {
    'PATH': '/sbin:/bin:/usr/sbin:/usr/bin',
    'HOME': '/'
}


def daemonize():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write('fork failed: {0}'.format(e.strerror))
        sys.exit(1)

    os.chdir('/')
    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write('fork failed: {0}'.format(e.strerror))
        sys.exit(1)

    sys.stdout.flush()
    sys.stderr.flush()
    try:
        devnull = os.open('/dev/null', os.O_RDWR)
        log = os.open('/var/tmp/serviced.log', os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    except OSError as e:
        sys.stderr.write('failed to open log file: {0}'.format(e.strerror))
        sys.exit(1)

    os.dup2(devnull, sys.stdin.fileno())
    os.dup2(log, sys.stdout.fileno())
    os.dup2(log, sys.stderr.fileno())


class JobState(enum.Enum):
    UNKNOWN = 'UNKNOWN'
    STARTING = 'STARTING'
    STOPPED = 'STOPPED'
    STOPPING = 'STOPPING'
    RUNNING = 'RUNNING'
    ERROR = 'ERROR'
    ENDED = 'ENDED'


class Job(object):
    def __init__(self, context):
        self.context = context
        self.anonymous = False
        self.disabled = False
        self.one_shot = False
        self.logger = None
        self.id = None
        self.label = None
        self.parent = None
        self.provides = set()
        self.requires = set()
        self.state = JobState.UNKNOWN
        self.program = None
        self.program_arguments = []
        self.pid = None
        self.pgid = None
        self.sid = None
        self.plist = None
        self.started_at = None
        self.exited_at = None
        self.keep_alive = False
        self.supports_checkin = False
        self.throttle_interval = 0
        self.exit_timeout = 10
        self.stdout_fd = None
        self.stdout_path = None
        self.stderr_fd = None
        self.stderr_path = None
        self.run_at_load = False
        self.user = None
        self.group = None
        self.umask = None
        self.last_exit_code = None
        self.failure_reason = None
        self.status_message = None
        self.status_extra = None
        self.environment = {}
        self.respawns = 0
        self.cv = Condition()

    @property
    def children(self):
        return (j for j in self.context.jobs if j.parent is self)

    def load(self, plist):
        self.state = JobState.STOPPED
        self.id = plist.get('ID', str(uuid.uuid4()))
        self.label = plist.get('Label')
        self.program = plist.get('Program')
        self.requires = set(plist.get('Requires', []))
        self.provides = set(plist.get('Provides', []))
        self.program_arguments = plist.get('ProgramArguments', [])
        self.stdout_path = plist.get('StandardOutPath')
        self.stderr_path = plist.get('StandardErrorPath')
        self.disabled = bool(plist.get('Disabled', False))
        self.run_at_load = bool(plist.get('RunAtLoad', False))
        self.keep_alive = bool(plist.get('KeepAlive', False))
        self.one_shot = bool(plist.get('OneShot', False))
        self.supports_checkin = bool(plist.get('SupportsCheckin', False))
        self.throttle_interval = int(plist.get('ThrottleInterval', 0))
        self.environment = plist.get('EnvironmentVariables', {})
        self.user = plist.get('UserName')
        self.group = plist.get('GroupName')
        self.umask = plist.get('Umask')
        self.logger = logging.getLogger('Job:{0}'.format(self.label))

        if first_or_default(lambda j: j.label == self.label, self.context.jobs.values()):
            raise RpcException(errno.EEXIST, 'Job with label {0} already exists'.format(self.label))

        if not self.program:
            self.program = self.program_arguments[0]

        if self.stdout_path:
            self.stdout_fd = os.open(self.stdout_path, os.O_WRONLY | os.O_APPEND)

        if self.stderr_path:
            self.stderr_fd = os.open(self.stderr_path, os.O_WRONLY | os.O_APPEND)

        if self.run_at_load:
            self.start()

    def load_anonymous(self, parent, pid):
        try:
            proc = bsd.kinfo_getproc(pid)
            command = proc.command
        except (LookupError, ProcessLookupError):
            # Exited too quickly, but let's add it anyway - it will be removed in next event
            command = 'unknown'

        with self.cv:
            self.parent = parent
            self.id = str(uuid.uuid4())
            self.pid = pid
            self.label = 'anonymous.{0}@{1}'.format(command, self.pid)
            self.logger = logging.getLogger('Job:{0}'.format(self.label))
            self.anonymous = True
            self.state = JobState.RUNNING
            self.cv.notify_all()

    def unload(self):
        self.logger.info('Unloading job')
        del self.context.jobs[self.id]

    def start(self):
        with self.cv:
            if self.state in (JobState.STARTING, JobState.RUNNING):
                return

            if not self.requires <= self.context.provides:
                return

            self.logger.info('Starting job')

            pid = os.fork()
            if pid == 0:
                os.kill(os.getpid(), signal.SIGSTOP)

                if not self.stdout_fd and not self.stderr_fd:
                    self.stdout_fd = self.stderr_fd = os.open('/var/tmp/{0}.{1}.log'.format(
                        self.label, os.getpid()),
                        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                        0o600
                    )

                os.dup2(os.open('/dev/null', os.O_RDONLY), sys.stdin.fileno())
                os.dup2(self.stdout_fd, sys.stdout.fileno())
                os.dup2(self.stderr_fd, sys.stderr.fileno())

                if self.user:
                    user = pwd.getpwnam(self.user)
                    os.setuid(user.pw_uid)

                if self.user:
                    group = grp.getgrnam(self.group)
                    os.setgid(group.gr_gid)

                if not self.program_arguments:
                    self.program_arguments = [self.program]

                bsd.closefrom(3)
                os.setsid()
                env = BASE_ENV.copy()
                env.update(self.environment)
                try:
                    os.execvpe(self.program, self.program_arguments, env)
                except:
                    os._exit(254)

            self.logger.debug('Started as PID {0}'.format(pid))
            self.pid = pid
            self.context.track_pid(self.pid)
            self.set_state(JobState.STARTING)

        os.waitpid(self.pid, os.WUNTRACED)
        os.kill(self.pid, signal.SIGCONT)

    def stop(self):
        with self.cv:
            if self.state == JobState.STOPPED:
                return

            self.logger.info('Stopping job')
            self.set_state(JobState.STOPPING)

            if not self.pid:
                self.set_state(JobState.STOPPED)
                return

            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                # Already dead
                self.set_state(JobState.STOPPED)

            if not self.cv.wait_for(lambda: self.state == JobState.STOPPED, self.exit_timeout):
                os.killpg(self.pgid, signal.SIGKILL)

            if not self.cv.wait_for(lambda: self.state == JobState.STOPPED, self.exit_timeout):
                self.logger.error('Unkillable process {0}'.format(self.pid))

    def send_signal(self, signo):
        if not self.pid:
            return

        os.kill(self.pid, signo)

    def checkin(self):
        with self.cv:
            self.logger.info('Service check-in')
            if self.supports_checkin:
                self.set_state(JobState.RUNNING)
                self.context.provide(self.provides)

    def push_status(self, status, extra=None):
        with self.cv:
            self.status_message = status
            self.status_extra = extra
            self.cv.notify_all()

        if self.label == 'org.freenas.dispatcher':
            self.context.init_dispatcher()

        self.context.emit_event('serviced.job.status', {
            'ID': self.id,
            'Label': self.label,
            'Reason': self.failure_reason,
            'Anonymous': self.anonymous,
            'Message': self.status_message,
            'Extra': self.status_extra
        })

    def pid_event(self, ev):
        if ev.fflags & select.KQ_NOTE_EXEC:
            self.pid_exec(ev)

        if ev.fflags & select.KQ_NOTE_EXIT:
            self.pid_exit(ev)

    def pid_exec(self, ev):
        try:
            proc = bsd.kinfo_getproc(self.pid)
            argv = list(proc.argv)
            command = proc.command
        except (LookupError, ProcessLookupError):
            # Exited too quickly, exit info will be catched in another event
            return

        self.logger.debug('Job did exec() into {0}'.format(argv))

        if self.anonymous:
            # Update label for anonymous jobs
            self.label = 'anonymous.{0}@{1}'.format(command, self.pid)
            self.logger = logging.getLogger('Job:{0}'.format(self.label))

        if self.state == JobState.STARTING:
            with self.cv:
                try:
                    self.sid = os.getsid(self.pid)
                    self.pgid = os.getpgid(self.pid)
                except ProcessLookupError:
                    # Exited too quickly after exec()
                    return

                if not self.supports_checkin:
                    self.set_state(JobState.RUNNING)
                    self.context.provide(self.provides)

    def pid_exit(self, ev):
        if not self.parent:
            # We need to reap direct children
            try:
                os.waitpid(self.pid, 0)
            except BaseException as err:
                self.logger.debug('waitpid() error: {0}'.format(err))

        with self.cv:
            self.logger.info('Job has exited with code {0}'.format(ev.data))
            self.pid = None
            self.last_exit_code = ev.data

            if self.state == JobState.STOPPING:
                self.set_state(JobState.STOPPED)
            else:
                if self.one_shot and self.last_exit_code == 0:
                    self.set_state(JobState.ENDED)
                else:
                    self.failure_reason = 'Process died with exit code {0}'.format(self.last_exit_code)
                    self.set_state(JobState.ERROR)

            if self.anonymous:
                del self.context.jobs[self.id]

    def set_state(self, new_state):
        # Must run locked
        if self.state != JobState.RUNNING and new_state == JobState.RUNNING:
            self.context.emit_event('serviced.job.started', {
                'ID': self.id,
                'PID': self.pid,
                'Label': self.label,
                'Anonymous': self.anonymous
            })

        if self.state != JobState.STOPPED and new_state == JobState.STOPPED:
            self.context.emit_event('serviced.job.stopped', {
                'ID': self.id,
                'Label': self.label,
                'Anonymous': self.anonymous
            })

        if self.state != JobState.ERROR and new_state == JobState.ERROR:
            self.context.emit_event('serviced.job.error', {
                'ID': self.id,
                'Label': self.label,
                'Reason': self.failure_reason,
                'Anonymous': self.anonymous
            })

        self.state = new_state
        self.cv.notify_all()

    def __getstate__(self):
        ret = {
            'ID': self.id,
            'ParentID': self.parent.id if self.parent else None,
            'Label': self.label,
            'Program': self.program,
            'ProgramArguments': self.program_arguments,
            'Provides': list(self.provides),
            'Requires': list(self.requires),
            'RunAtLoad': self.run_at_load,
            'KeepAlive': self.keep_alive,
            'State': self.state.name,
            'LastExitStatus': self.last_exit_code,
            'PID': self.pid
        }

        if self.failure_reason:
            ret['FailureReason'] = self.failure_reason

        if self.stdout_path:
            ret['StandardOutPath'] = self.stdout_path

        if self.stdout_path:
            ret['StandardErrorPath'] = self.stderr_path

        if self.environment:
            ret['EnvironmentVariables'] = self.environment

        return ret


class ManagementService(RpcService):
    def __init__(self, context):
        self.context = context

    def shutdown(self):
        def doit():
            for job in list(self.context.jobs.values()):
                job.stop()

            for _ in range(0, SHUTDOWN_TIMEOUT):
                time.sleep(1)
                if all(j.state in (JobState.STOPPED, JobState.ERROR) for j in self.context.jobs.values()):
                    break

            self.context.shutdown()

        Thread(target=doit, daemon=True).start()


class JobService(RpcService):
    def __init__(self, context):
        self.context = context

    @generator
    def query(self, filter=None, params=None):
        with self.context.lock:
            return q.query(self.context.jobs.values(), *(filter or []), **(params or {}))

    def load(self, plist):
        job = Job(self.context)
        job.load(plist)
        with self.context.lock:
            self.context.jobs[job.id] = job

    def unload(self, name_or_id):
        with self.context.lock:
            job = first_or_default(lambda j: j.label == name_or_id or j.id == name_or_id, self.context.jobs.values())
            if not job:
                raise RpcException(errno.ENOENT, 'Job {0} not found'.format(name_or_id))

        job.stop()
        job.unload()

    def start(self, name_or_id, wait=False):
        with self.context.lock:
            job = first_or_default(lambda j: j.label == name_or_id or j.id == name_or_id, self.context.jobs.values())
            if not job:
                raise RpcException(errno.ENOENT, 'Job {0} not found'.format(name_or_id))

        job.start()
        if wait:
            self.wait(name_or_id, (JobState.RUNNING, JobState.ERROR))

    def stop(self, name_or_id, wait=False):
        with self.context.lock:
            job = first_or_default(lambda j: j.label == name_or_id or j.id == name_or_id, self.context.jobs.values())
            if not job:
                raise RpcException(errno.ENOENT, 'Job {0} not found'.format(name_or_id))

        job.stop()
        if wait:
            self.wait(name_or_id, (JobState.STOPPED, JobState.ERROR))

    def restart(self, name_or_id):
        self.stop(name_or_id, True)
        self.start(name_or_id, True)

    def send_signal(self, name_or_id, signo):
        with self.context.lock:
            job = first_or_default(lambda j: j.label == name_or_id or j.id == name_or_id, self.context.jobs.values())
            if not job:
                raise RpcException(errno.ENOENT, 'Job {0} not found'.format(name_or_id))

        job.send_signal(signo)

    def get(self, name_or_id):
        with self.context.lock:
            job = first_or_default(lambda j: j.label == name_or_id or j.id == name_or_id, self.context.jobs.values())
            if not job:
                raise RpcException(errno.ENOENT, 'Job {0} not found'.format(name_or_id))

        return job.__getstate__()

    def get_by_pid(self, pid, fuzzy=False):
        with self.context.lock:
            def match(j):
                return j.pid == pid

            def fuzzy_match(j):
                if j.parent and j.parent.pid == pid:
                    return True

                return j.pid == pid

            job = first_or_default(fuzzy_match if fuzzy else match, self.context.jobs.values())
            if job.parent:
                job = job.parent

            if not job:
                raise RpcException(errno.ENOENT, 'Job for PID {0} not found'.format(pid))

        return job.__getstate__()

    def wait(self, name_or_id, states):
        with self.context.lock:
            job = first_or_default(lambda j: j.label == name_or_id or j.id == name_or_id, self.context.jobs.values())
            if not job:
                raise RpcException(errno.ENOENT, 'Job {0} not found'.format(name_or_id))

        with job.cv:
            job.cv.wait_for(lambda: job.state in states)
            return job.state

    def checkin(self):
        sender = get_sender()
        job = self.context.job_by_pid(sender.credentials['pid'])
        if not job:
            raise RpcException(errno.EINVAL, 'Unknown job')

        job.checkin()

    def push_status(self, status, extra=None):
        sender = get_sender()
        job = self.context.job_by_pid(sender.credentials['pid'])
        if not job:
            raise RpcException(errno.EINVAL, 'Unknown job')

        job.push_status(status, extra)


class Context(object):
    def __init__(self):
        self.server = None
        self.client = None
        self.jobs = {}
        self.provides = set()
        self.lock = RLock()
        self.kq = select.kqueue()
        self.devnull = os.open('/dev/null', os.O_RDWR)
        self.logger = logging.getLogger('Context')
        self.rpc = RpcContext()
        self.rpc.register_service_instance('serviced.management', ManagementService(self))
        self.rpc.register_service_instance('serviced.job', JobService(self))

    def init_dispatcher(self):
        if self.client and self.client.connected:
            return

        def on_error(reason, **kwargs):
            if reason in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
                self.logger.warning('Connection to dispatcher lost')
                self.connect()

        self.client = Client()
        self.client.on_error(on_error)
        self.connect()

    def init_server(self, address):
        self.server = Server(self)
        self.server.rpc = self.rpc
        self.server.streaming = True
        self.server.start(address, transport_options={'permissions': 0o777})
        thread = Thread(target=self.server.serve_forever)
        thread.name = 'ServerThread'
        thread.daemon = True
        thread.start()

    def provide(self, targets):
        def doit():
            self.logger.debug('Adding dependency targets: {0}'.format(', '.join(targets)))
            with self.lock:
                self.provides |= targets
                for job in list(self.jobs.values()):
                    if job.state == JobState.STOPPED and job.requires <= self.provides:
                        job.start()

        if targets:
            Timer(2, doit).start()

    def job_by_pid(self, pid):
        job = first_or_default(lambda j: j.pid == pid, self.jobs.values())
        return job

    def event_loop(self):
        while True:
            with contextlib.suppress(InterruptedError):
                for ev in self.kq.control(None, MAX_EVENTS):
                    self.logger.log(TRACE, 'New event: {0}'.format(ev))
                    if ev.filter == select.KQ_FILTER_PROC:
                        job = self.job_by_pid(ev.ident)
                        if job:
                            job.pid_event(ev)
                            continue

                        if ev.fflags & select.KQ_NOTE_CHILD:
                            if ev.fflags & select.KQ_NOTE_EXIT:
                                continue

                            pjob = self.job_by_pid(ev.data)
                            if not pjob:
                                self.untrack_pid(ev.ident)
                                continue

                            # Stop tracking at session ID boundary
                            try:
                                if pjob.pgid != os.getpgid(ev.ident):
                                    self.untrack_pid(ev.ident)
                                    continue
                            except ProcessLookupError:
                                continue

                            with self.lock:
                                job = Job(self)
                                job.load_anonymous(pjob, ev.ident)
                                self.jobs[job.id] = job
                                self.logger.info('Added job {0}'.format(job.label))

    def track_pid(self, pid):
        ev = select.kevent(
            pid,
            select.KQ_FILTER_PROC,
            select.KQ_EV_ADD | select.KQ_EV_ENABLE,
            select.KQ_NOTE_EXIT | select.KQ_NOTE_EXEC | select.KQ_NOTE_FORK | select.KQ_NOTE_TRACK,
            0, 0
        )

        self.kq.control([ev], 0)

    def untrack_pid(self, pid):
        ev = select.kevent(
            pid,
            select.KQ_FILTER_PROC,
            select.KQ_EV_DELETE,
            0, 0, 0
        )

        with contextlib.suppress(FileNotFoundError):
            self.kq.control([ev], 0)

    def emit_event(self, name, args):
        self.server.broadcast_event(name, args)
        if self.client and self.client.connected:
            self.client.emit_event(name, args)

    def connect(self):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('serviced')
                self.client.enable_server(self.rpc)
                self.client.resume_service('serviced.job')
                self.client.resume_service('serviced.management')
                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

    def bootstrap(self):
        def doit():
            with self.lock:
                job = Job(self)
                job.load({
                    'Label': 'org.freenas.serviced.bootstrap',
                    'ProgramArguments': BOOTSTRAP_JOB,
                    'OneShot': True,
                    'RunAtLoad': True,
                })

                self.jobs[job.id] = job

        Thread(target=doit).start()

    def shutdown(self):
        self.client.disconnect()
        self.server.close()
        sys.exit(0)

    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-s', metavar='SOCKET', default=DEFAULT_SOCKET_ADDRESS, help='Socket address to listen on')
        args = parser.parse_args()

        configure_logging('/var/log/serviced.log', 'DEBUG', file=True)
        bsd.setproctitle('serviced')
        self.logger.info('Started')
        self.init_server(args.s)
        self.bootstrap()
        self.event_loop()


if __name__ == '__main__':
    daemonize()
    c = Context()
    c.main()
