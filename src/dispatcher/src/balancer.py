#+
# Copyright 2014 iXsystems, Inc.
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

import os
import gevent
import logging
import traceback
import errno
import copy
import uuid
import fnmatch
import inspect
import subprocess
import bsd
import signal
from lib.freebsd import get_sysctl
from threading import Condition
from datetime import datetime
from freenas.dispatcher import validator, Password
from freenas.dispatcher.fd import FileDescriptor
from freenas.dispatcher.rpc import RpcException
from gevent.queue import Queue
from gevent.lock import RLock
from gevent.event import Event, AsyncResult
from gevent.subprocess import Popen
from gevent.fileobject import FileObjectPosix
from freenas.utils import first_or_default
from resources import Resource
from auth import FileToken
from task import (
    TaskException, TaskAbortException, VerifyException, ValidationException,
    TaskStatus, TaskState, TaskDescription
)
import collections


TASKWORKER_PATH = '/usr/local/libexec/taskworker'
ERROR_TYPES = {
    'RpcException': RpcException,
    'TaskException': TaskException,
    'TaskAbortException': TaskAbortException,
    'ValidationException': ValidationException
}


class OtherException(TaskException):
    def __init__(self, code, message, type, stacktrace, extra):
        super(OtherException, self).__init__(code, message, stacktrace=stacktrace, extra=extra)
        self.type = type

    def __str__(self):
        return '{0}: {1} (original exception type: {2})'.format(
            errno.errorcode.get(self.code, '<unknown errno {0}>'.format(self.code)),
            self.message,
            self.type
        )


class WorkerState(object):
    IDLE = 'IDLE'
    ASSIGNED = 'ASSIGNED'
    EXECUTING = 'EXECUTING'
    STARTING = 'STARTING'


class TaskExecutor(object):
    def __init__(self, balancer, index):
        self.balancer = balancer
        self.index = index
        self.task = None
        self.proc = None
        self.pid = None
        self.conn = None
        self.state = WorkerState.STARTING
        self.key = str(uuid.uuid4())
        self.result = AsyncResult()
        self.exiting = False
        self.killed = False
        self.thread = gevent.spawn(self.executor)
        self.cv = Condition()
        self.status_lock = RLock()

    def checkin(self, conn):
        with self.cv:
            self.balancer.logger.debug('Check-in of worker #{0} (key {1})'.format(self.index, self.key))
            self.conn = conn
            self.state = WorkerState.IDLE
            self.cv.notify_all()

    def put_progress(self, progress):
        st = TaskStatus(None)
        st.__setstate__(progress)
        self.task.set_state(progress=st)

    def put_status(self, status):
        with self.cv:
            # Try to collect rusage at this point, when process is still alive
            try:
                kinfo = self.balancer.dispatcher.threaded(bsd.kinfo_getproc, self.pid)
                self.task.rusage = kinfo.rusage
            except LookupError:
                pass

            if status['status'] == 'ROLLBACK':
                self.task.set_state(TaskState.ROLLBACK)

            if status['status'] == 'FINISHED':
                self.result.set(status['result'])

            if status['status'] == 'FAILED':
                error = status['error']

                if error['type'] in ERROR_TYPES:
                    cls = ERROR_TYPES[error['type']]
                    exc = cls(
                        code=error['code'],
                        message=error['message'],
                        stacktrace=error['stacktrace'],
                        extra=error.get('extra')
                    )
                else:
                    exc = OtherException(
                        code=error['code'],
                        message=error['message'],
                        stacktrace=error['stacktrace'],
                        type=error['type'],
                        extra=error.get('extra'),
                    )

                self.result.set_exception(exc)

    def put_warning(self, warning):
        self.task.add_warning(warning)

    def update_env(self, env):
        self.conn.call_sync('taskproxy.update_env', env)

    def run(self, task):
        def match_file(module, f):
            name, ext = os.path.splitext(f)
            return module == name and ext in ['.py', '.pyc', '.so']

        with self.cv:
            self.cv.wait_for(lambda: self.state == WorkerState.ASSIGNED)
            self.result = AsyncResult()
            self.task = task
            self.task.set_state(TaskState.EXECUTING)
            self.state = WorkerState.EXECUTING
            self.cv.notify_all()

        self.balancer.logger.debug('Actually starting task {0}'.format(task.id))

        filename = None
        module_name = inspect.getmodule(task.clazz).__name__
        for dir in self.balancer.dispatcher.plugin_dirs:
            found = False
            try:
                for root, _, files in os.walk(dir):
                    file = first_or_default(lambda f: match_file(module_name, f), files)
                    if file:
                        filename = os.path.join(root, file)
                        found = True
                        break

                if found:
                    break
            except OSError:
                continue

        try:
            self.conn.call_sync('taskproxy.run', {
                'id': task.id,
                'user': task.user,
                'class': task.clazz.__name__,
                'filename': filename,
                'args': task.args,
                'debugger': task.debugger,
                'environment': task.environment,
                'hooks': task.hooks,
            })
        except RpcException as e:
            self.balancer.logger.warning('Cannot start task {0} on executor #{1}: {2}'.format(
                task.id,
                self.index,
                str(e)
            ))

            self.balancer.logger.warning('Killing unresponsive task executor #{0} (pid {1})'.format(
                self.index,
                self.proc.pid
            ))

            self.terminate()

        try:
            self.result.get()
        except BaseException as e:
            if isinstance(e, OtherException):
                self.balancer.dispatcher.report_error(
                    'Task {0} raised invalid exception'.format(self.task.name),
                    e
                )

            if isinstance(e, TaskAbortException):
                self.task.set_state(TaskState.ABORTED, TaskStatus(0, 'aborted'))
            else:
                self.task.error = serialize_error(e)
                self.task.set_state(TaskState.FAILED, TaskStatus(0, str(e), extra={
                    "stacktrace": traceback.format_exc()
                }))

            with self.cv:
                self.task.ended.set()

                if self.state == WorkerState.EXECUTING:
                    self.state = WorkerState.IDLE
                    self.cv.notify_all()

            self.balancer.task_exited(self.task)
            return

        with self.cv:
            self.task.result = self.result.value
            self.task.set_state(TaskState.FINISHED, TaskStatus(100, ''))
            self.task.ended.set()
            if self.state == WorkerState.EXECUTING:
                self.state = WorkerState.IDLE
                self.cv.notify_all()

        self.balancer.task_exited(self.task)

    def abort(self):
        self.balancer.logger.info("Trying to abort task #{0}".format(self.task.id))
        # Try to abort via RPC. If this fails, kill process
        try:
            # If task supports abort protocol we don't need to worry about subtasks - it's task
            # responsibility to kill them
            self.conn.call_sync('taskproxy.abort')
        except RpcException as err:
            self.balancer.logger.warning("Failed to abort task #{0} gracefully: {1}".format(self.task.id, str(err)))
            self.balancer.logger.warning("Killing process {0}".format(self.pid))
            self.killed = True
            self.terminate()

            # Now kill all the subtasks
            for subtask in filter(lambda t: t.parent is self.task, self.balancer.task_list):
                self.balancer.logger.warning("Aborting subtask {0} because parent task {1} died".format(
                    subtask.id,
                    self.task.id
                ))
                self.balancer.abort(subtask.id)

    def terminate(self):
        try:
            self.proc.terminate()
        except OSError:
            self.balancer.logger.warning('Executor process with PID {0} already dead'.format(self.proc.pid))

    def executor(self):
        while not self.exiting:
            try:
                self.proc = Popen(
                    [TASKWORKER_PATH, self.key, str(self.index)],
                    close_fds=True,
                    preexec_fn=os.setpgrp,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)

                self.pid = self.proc.pid
                self.balancer.logger.debug('Started executor #{0} as PID {1}'.format(self.index, self.pid))
            except OSError:
                self.result.set_exception(TaskException(errno.EFAULT, 'Cannot spawn task executor'))
                self.balancer.logger.error('Cannot spawn task executor #{0}'.format(self.index))
                return

            for line in self.proc.stdout:
                line = line.decode('utf8')
                self.balancer.logger.debug('Executor #{0}: {1}'.format(self.index, line.strip()))
                if self.task:
                    self.task.output += line

            self.proc.wait()

            with self.cv:
                self.state = WorkerState.STARTING
                self.cv.notify_all()

            if self.proc.returncode == -signal.SIGTERM:
                self.balancer.logger.info(
                    'Executor process with PID {0} was terminated gracefully'.format(
                        self.proc.pid
                    )
                )
            else:
                self.balancer.logger.error('Executor process with PID {0} died abruptly with exit code {1}'.format(
                    self.proc.pid,
                    self.proc.returncode)
                )

            if self.killed:
                self.result.set_exception(TaskException(errno.EFAULT, 'Task killed'))
            else:
                self.result.set_exception(TaskException(errno.EFAULT, 'Task executor died'))
            gevent.sleep(1)

    def die(self):
        self.exiting = True
        if self.proc:
            self.terminate()


class Task(object):
    def __init__(self, dispatcher, name=None):
        self.dispatcher = dispatcher
        self.balancer = dispatcher.balancer
        self.created_at = None
        self.started_at = None
        self.finished_at = None
        self.id = None
        self.name = name
        self.clazz = None
        self.args = None
        self.user = None
        self.session_id = None
        self.error = None
        self.state = TaskState.CREATED
        self.description = None
        self.progress = TaskStatus(None)
        self.resources = []
        self.warnings = []
        self.environment = {}
        self.hooks = {}
        self.instance = None
        self.parent = None
        self.result = None
        self.output = ''
        self.rusage = None
        self.slock = RLock()
        self.ended = Event()
        self.debugger = None
        self.executor = None
        self.strict_verify = None

    def __getstate__(self):
        return {
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "user": self.user,
            "resources": self.resources,
            "description": self.get_description().__getstate__(),
            "session": self.session_id,
            "name": self.name,
            "parent": self.parent.id if self.parent else None,
            "args": remove_dots(self.args),
            "result": remove_dots(self.result),
            "state": self.state,
            "output": self.output,
            "rusage": self.rusage,
            "error": self.error,
            "warnings": self.warnings,
            "debugger": self.debugger,
            "environment": self.environment,
            "abortable": True if (hasattr(self.clazz, 'abort') and isinstance(self.clazz.abort, collections.Callable)) else False
        }

    def __emit_progress(self):
        self.dispatcher.dispatch_event("task.progress", {
            "id": self.id,
            "name": self.name,
            "state": self.state,
            "nolog": True,
            "percentage": self.progress.percentage,
            "message": self.progress.message,
            "extra": self.progress.extra,
            "abortable": True if (hasattr(self.instance, 'abort') and isinstance(self.instance.abort, collections.Callable)) else False
        })

    def start(self):
        try:
            self.balancer.assign_executor(self)
        except OverflowError:
            self.set_state(TaskState.FAILED, error='Out of executors')
            self.ended.set()
            self.balancer.task_exited(self)

        # Start actual task
        return gevent.spawn(self.executor.run, self)

    def join(self, timeout=None):
        self.ended.wait(timeout)

    def set_state(self, state=None, progress=None, error=None):
        with self.slock:
            if state:
                self.state = state

            event = {'id': self.id, 'name': self.name, 'state': self.state}

            if error:
                self.error = error

            if self.state == TaskState.EXECUTING:
                if not self.started_at:
                    self.started_at = datetime.utcnow()
                event['started_at'] = self.started_at

            if self.state == TaskState.FINISHED:
                self.finished_at = datetime.utcnow()
                self.progress = TaskStatus(100)
                event['finished_at'] = self.finished_at
                event['result'] = self.result

            if self.state in (TaskState.FAILED, TaskState.ABORTED):
                self.progress = TaskStatus(0)

            self.dispatcher.dispatch_event('task.created' if self.state == TaskState.CREATED else 'task.updated', event)
            self.dispatcher.datastore_log.update('tasks', self.id, self)
            self.dispatcher.dispatch_event('task.changed', {
                'operation': 'create' if state == TaskState.CREATED else 'update',
                'ids': [self.id]
            })

            if progress and self.state not in (TaskState.FINISHED, TaskState.FAILED, TaskState.ABORTED):
                self.progress = progress
                self.__emit_progress()

            if self.state in (TaskState.FINISHED, TaskState.FAILED, TaskState.ABORTED):
                try:
                    # Remove all subtasks
                    for i in filter(lambda t: t.parent is self, self.balancer.task_list):
                        self.balancer.task_list.remove(i)

                    # If top-level task, also remove self
                    if self.parent is None:
                        self.balancer.task_list.remove(self)
                except ValueError:
                    # failed in verify stage
                    pass

    def set_env(self, key, value):
        self.environment[key] = value
        self.dispatcher.datastore_log.update('tasks', self.id, self)

    def set_output(self, output):
        self.output = output
        self.dispatcher.datastore_log.update('tasks', self.id, self)

    def add_warning(self, warning):
        self.warnings.append(warning)
        self.dispatcher.datastore_log.update('tasks', self.id, self)
        self.dispatcher.dispatch_event('task.changed', {
            'operation': 'update',
            'ids': [self.id]
        })

    def get_description(self):
        if not self.description:
            if not self.clazz:
                return TaskDescription(self.name)

            return TaskDescription(self.clazz.early_describe())

        if isinstance(self.description, TaskDescription):
            return self.description

        return TaskDescription(str(self.description))


class Balancer(object):
    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.task_list = []
        self.task_queue = Queue()
        self.resource_graph = dispatcher.resource_graph
        self.threads = []
        self.executors = []
        self.logger = logging.getLogger('Balancer')
        self.dispatcher.require_collection('tasks', 'serial', type='log')
        self.create_initial_queues()
        self.schedule_lock = RLock()
        self.distribution_lock = RLock()
        self.debugger = None
        self.debugged_tasks = None
        self.dispatcher.register_event_type('task.changed')

    def clean_stale_tasks(self):
        # Lets try to get `EXECUTING|WAITING|CREATED` state tasks
        # from the previous dispatcher instance and set their
        # states to 'FAILED' since they are no longer running
        # in this instance of the dispatcher
        for stale_task in self.dispatcher.datastore_log.query(
            'tasks',
            ('state', 'in', ['EXECUTING', 'WAITING', 'CREATED'])
        ):
            self.logger.info('Stale task ID: {0}, name: {1} being set to FAILED'.format(
                stale_task['id'],
                stale_task['name']
            ))

            stale_task.update({
                'state': 'FAILED',
                'error': {
                    'type': 'TaskException',
                    'message': 'dispatcher process died',
                    'code': errno.EINTR,
                    'stacktrace': '',
                    'extra': None
                }
            })

            self.dispatcher.datastore_log.update('tasks', stale_task['id'], stale_task)

    def create_initial_queues(self):
        self.resource_graph.add_resource(Resource('system'))

    def start_executors(self):
        for i in range(0, max(get_sysctl("hw.ncpu"), 2)):
            self.logger.info('Starting task executor #{0}...'.format(i))
            self.executors.append(TaskExecutor(self, i))

    def start(self):
        self.clean_stale_tasks()
        self.start_executors()
        self.threads.append(gevent.spawn(self.distribution_thread))
        self.logger.info("Started")

    def schema_to_list(self, schema):
        return {
            'type': 'array',
            'items': schema,
            'minItems': sum([1 for x in schema if 'mandatory' in x and x['mandatory']]),
            'maxItems': len(schema)
        }

    def verify_schema(self, clazz, args, strict=False):
        params_schema = clazz._get_schema()
        if not params_schema:
            return []

        schema = self.schema_to_list(params_schema)
        val = validator.create_validator(schema, resolver=self.dispatcher.rpc.get_schema_resolver(schema))
        if strict:
            val.fail_read_only = True
        else:
            val.remove_read_only = True

        return list(val.iter_errors(args))

    def submit(self, name, args, sender, env=None):
        if name not in self.dispatcher.tasks:
            self.logger.warning("Cannot submit task: unknown task type %s", name)
            raise RpcException(errno.EINVAL, "Unknown task type {0}".format(name))

        task = Task(self.dispatcher, name)
        task.user = sender.user.name
        task.session_id = sender.session_id
        task.created_at = datetime.utcnow()
        task.clazz = self.dispatcher.tasks[name]
        task.hooks = self.dispatcher.task_hooks.get(name, {})
        task.args = copy.deepcopy(args)
        task.strict_verify = 'strict_validation' in sender.enabled_features

        if env:
            if not isinstance(env, dict):
                raise ValueError('env must be a dict')

            task.environment = copy.deepcopy(env)

        if self.debugger:
            for m in self.debugged_tasks:
                if fnmatch.fnmatch(name, m):
                    task.debugger = self.debugger

        if 'RUN_AS_USER' in task.environment:
            task.user = task.environment['RUN_AS_USER']

        task.id = self.dispatcher.datastore_log.insert("tasks", task)
        task.environment['SENDER_ADDRESS'] = sender.client_address
        task.environment['ID'] = task.id
        task.set_state(TaskState.CREATED)
        self.task_queue.put(task)
        self.logger.info("Task %d submitted (type: %s, class: %s)", task.id, name, task.clazz)
        return task.id

    def submit_with_upload(self, task_name, args, sender, env=None):
        task_metadata = self.dispatcher.tasks[task_name]._get_metadata()
        schema = task_metadata['schema']

        if schema is None:
            raise RpcException(
                errno.ENOENT, "Task {0} has no schema associated with it".format(task_name)
            )
        upload_token_list = []
        for idx, arg in enumerate(schema):
            if arg.get('type') == 'fd':
                rfd, wfd = os.pipe()
                token = self.dispatcher.token_store.issue_token(FileToken(
                    user=sender.user,
                    lifetime=600,
                    direction='upload',
                    file=FileObjectPosix(wfd, 'wb', close=True),
                    name=str(uuid.uuid4()),
                    size=None
                ))
                upload_token_list.append(token)
                args[idx] = FileDescriptor(rfd)
        task_id = self.submit(task_name, args, sender, env)
        return task_id, upload_token_list

    def submit_with_download(self, task_name, args, sender, env=None):
        task_metadata = self.dispatcher.tasks[task_name]._get_metadata()
        schema = task_metadata['schema']
        url_list = []

        if schema is None:
            raise RpcException(
                errno.ENOENT, "Task {0} has no schema associated with it".format(task_name)
            )

        for idx, arg in enumerate(schema):
            if arg.get('type') == 'fd':
                rfd, wfd = os.pipe()
                url_list.append("/dispatcher/filedownload?token={0}".format(
                    self.dispatcher.token_store.issue_token(FileToken(
                        user=sender.user,
                        lifetime=600,
                        direction='download',
                        file=FileObjectPosix(rfd, 'rb', close=True),
                        name=args[idx]
                    ))
                ))
                args[idx] = FileDescriptor(wfd)
        task_id = self.submit(task_name, args, sender, env)
        return task_id, url_list

    def verify_subtask(self, parent, name, args):
        clazz = self.dispatcher.tasks[name]
        instance = clazz(self.dispatcher)
        return instance.verify(*args)

    def run_subtask(self, parent, name, args, env=None):
        args = list(args)
        task = Task(self.dispatcher, name)
        task.created_at = datetime.utcnow()
        task.clazz = self.dispatcher.tasks[name]
        task.hooks = self.dispatcher.task_hooks.get(name, {})
        task.args = args
        task.instance = task.clazz(self.dispatcher)
        task.instance.verify(*task.args)
        task.description = task.instance.describe(*task.args)
        task.id = self.dispatcher.datastore_log.insert("tasks", task)
        task.parent = parent
        task.environment = {'ID': task.id}

        if parent:
            task.environment = copy.deepcopy(parent.environment)
            task.environment['parent'] = parent.id
            task.user = parent.user

        if env:
            if not isinstance(env, dict):
                raise ValueError('env must be a dict')

            task.environment.update(env)

        if self.debugger:
            for m in self.debugged_tasks:
                if fnmatch.fnmatch(name, m):
                    task.debugger = self.debugger

        task.set_state(TaskState.CREATED)
        self.task_list.append(task)

        task.start()
        return task

    def join_subtasks(self, *tasks):
        for i in tasks:
            i.join()

    def abort(self, id, error=None):
        task = self.get_task(id)
        if not task:
            self.logger.warning("Cannot abort task: unknown task id %d", id)
            return

        success = False
        if task.started_at is None:
            success = True
        else:
            try:
                task.executor.abort()
            except:
                pass
        if success:
            task.ended.set()
            if error:
                task.set_state(TaskState.FAILED, TaskStatus(0), serialize_error(error))
                self.logger.debug("Task ID: %d, name: %s aborted with error", task.id, task.name)
            else:
                task.set_state(TaskState.ABORTED, TaskStatus(0, "Aborted"))
                self.logger.debug("Task ID: %d, name: %s aborted by user", task.id, task.name)

    def task_exited(self, task):
        self.resource_graph.release(*task.resources)
        self.schedule_tasks(True)

    def schedule_tasks(self, exit=False):
        """
        This function is called when:
        1) any new task is submitted to any of the queues
        2) any task exists
        """
        with self.schedule_lock:
            started = 0
            executing_tasks = [t for t in self.task_list if t.state == TaskState.EXECUTING]
            waiting_tasks = [t for t in self.task_list if t.state == TaskState.WAITING]

            for task in waiting_tasks:
                if not self.resource_graph.can_acquire(*task.resources):
                    continue

                self.resource_graph.acquire(*task.resources)
                self.threads.append(task.start())
                started += 1

            if not started and not executing_tasks and (exit or len(waiting_tasks) == 1):
                for task in waiting_tasks:
                    # Check whether or not task waits on nonexistent resources. If it does,
                    # abort it 'cause there's no chance anymore that missing resources will appear.
                    missing_resources = [r for r in task.resources if self.resource_graph.get_resource(r) is None]
                    if missing_resources:
                        self.logger.warning('Aborting task {0}: deadlock'.format(task.id))
                        self.abort(task.id, VerifyException(
                            errno.EBUSY,
                            'Resource deadlock avoided, missing resources: {0}'.format(', '.join(missing_resources))
                        ))

    def distribution_thread(self):
        while True:
            self.task_queue.peek()
            self.distribution_lock.acquire()
            task = self.task_queue.get()

            try:
                self.logger.debug("Picked up task %d: %s with args %s", task.id, task.name, task.args)

                errors = self.verify_schema(self.dispatcher.tasks[task.name], task.args, task.strict_verify)
                if len(errors) > 0:
                    errors = list(validator.serialize_errors(errors))
                    self.logger.warning("Cannot submit task {0}: schema verification failed with errors {1}".format(
                        task.name,
                        errors
                    ))
                    raise ValidationException(extra=errors)

                task.instance = task.clazz(self.dispatcher)
                task.resources = task.instance.verify(*task.args)
                task.description = task.instance.describe(*task.args)

                if type(task.resources) is not list:
                    raise ValueError("verify() returned something else than resource list")

            except Exception as err:
                self.logger.warning("Cannot verify task %d: %s", task.id, err)
                task.set_state(TaskState.FAILED, TaskStatus(0), serialize_error(err))
                task.ended.set()
                self.distribution_lock.release()

                if not isinstance(err, VerifyException):
                    self.dispatcher.report_error('Task {0} verify() method raised invalid exception'.format(err), err)

                continue

            task.set_state(TaskState.WAITING)
            self.task_list.append(task)
            self.distribution_lock.release()
            self.schedule_tasks()
            if task.resources:
                self.logger.debug("Task %d assigned to resources %s", task.id, ','.join(task.resources))

    def assign_executor(self, task):
        for i in self.executors:
            with i.cv:
                if i.state == WorkerState.IDLE:
                    self.logger.info("Task %d assigned to executor #%d", task.id, i.index)
                    task.executor = i
                    i.state = WorkerState.ASSIGNED
                    return

        # Out of executors! Need to spawn new one
        executor = TaskExecutor(self, len(self.executors))
        self.executors.append(executor)
        with executor.cv:
            executor.cv.wait_for(lambda: executor.state == WorkerState.IDLE)
            executor.state = WorkerState.ASSIGNED
            task.executor = executor
            self.logger.info("Task %d assigned to executor #%d", task.id, executor.index)

    def dispose_executors(self):
        for i in self.executors:
            i.die()

    def get_active_tasks(self):
        return [x for x in self.task_list if x.state in (
            TaskState.CREATED,
            TaskState.WAITING,
            TaskState.EXECUTING
        )]

    def get_tasks(self, type=None):
        if type is None:
            return self.task_list

        return [x for x in self.task_list if x.state == type]

    def get_task(self, id):
        self.distribution_lock.acquire()
        t = first_or_default(lambda x: x.id == id, self.task_list)
        if not t:
            t = first_or_default(lambda x: x.id == id, self.task_queue.queue)

        self.distribution_lock.release()
        return t

    def get_executor_by_key(self, key):
        return first_or_default(lambda t: t.key == key, self.executors)

    def get_executor_by_sender(self, sender):
        return first_or_default(lambda t: t.conn == sender, self.executors)

    def update_executor_environment(self, env):
        for e in self.executors:
            e.update_env(env)


def serialize_error(err):
    ret = {
        'type': type(err).__name__,
        'message': str(err),
        'stacktrace': err.stacktrace if hasattr(err, 'stacktrace') else traceback.format_exc()
    }

    if isinstance(err, RpcException):
        ret['code'] = err.code
        ret['message'] = err.message
        if err.extra:
            ret['extra'] = err.extra
    else:
        ret['code'] = errno.EFAULT

    return ret


def replace_invalid_chars(s):
    s = s.replace('.', '+')
    s = s.replace('$', '%')
    return s


def remove_dots(obj):
    if isinstance(obj, FileDescriptor):
        return {'fd': obj.fd}

    if isinstance(obj, Password):
        return str(obj)

    if isinstance(obj, dict):
        return {replace_invalid_chars(k): remove_dots(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple)):
        return [remove_dots(x) for x in obj]

    if isinstance(obj, int) and obj > 2**32:
        return str(obj)

    return obj
