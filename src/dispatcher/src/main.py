#
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

import gevent.monkey
gevent.monkey.patch_all()

import copy
import os
import sys
import re
import fnmatch
import json
import datetime
import logging
import logging.config
import logging.handlers
import argparse
import signal
import time
import errno
import contextlib
import tempfile
import cgi
import subprocess
import struct
import termios
import fcntl
import traceback
import websocket  # do not remove - we import it only for side effects

import gevent
from bsd import setproctitle, fnmatch as cfnmatch
from io import UnsupportedOperation
from pyee import EventEmitter
from gevent.threadpool import ThreadPool
from gevent.os import tp_read, tp_write, forkpty_and_watch
from gevent.queue import Queue
from gevent.lock import RLock
from gevent.event import Event
from gevent.pywsgi import WSGIServer
from geventwebsocket import WebSocketApplication, WebSocketError

from datastore import get_datastore
from datastore.migrate import migrate_db, MigrationException
from datastore.config import ConfigStore
from freenas.dispatcher.jsonenc import loads, dumps
from freenas.dispatcher.rpc import RpcContext, RpcException, ServerLockProxy
from freenas.dispatcher.server import Server, ServerConnection
from resources import ResourceGraph, ResourceTracker
from services import ManagementService, DebugService, EventService, TaskService
from services import LockService, PluginService, ShellService
from schemas import register_general_purpose_schemas
from balancer import Balancer
from auth import PasswordAuthenticator, TokenStore, Token, User, Service
from freenas.utils import FaultTolerantLogHandler, load_module_from_file, serialize_exception
from freenas.utils.trace_logger import TraceLogger, TRACE
from freenas.serviced import checkin, push_status
from freenas.logd import LogdLogHandler

DEFAULT_CONFIGFILE = '/usr/local/etc/middleware.conf'
LOGGING_FORMAT = '%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s'
FEATURES = ['streaming_responses', 'strict_validation']
trace_log_file = None


def trace_log(message, *args):
    global trace_log_file

    if os.getenv('DISPATCHER_TRACE'):
        if not trace_log_file:
            try:
                trace_log_file = open('/var/tmp/dispatcher-trace.{0}.log'.format(os.getpid()), 'w')
            except OSError:
                pass

        print(message.format(*args), file=trace_log_file)
        trace_log_file.flush()


def match_event(name, pat):
    if isinstance(pat, str):
        return cfnmatch(name, pat)

    if isinstance(pat, re._pattern_type):
        return pat.match(name) is not None


class Plugin(object):
    UNLOADED = 1
    LOADED = 2
    ERROR = 3

    def __init__(self, dispatcher, filename=None):
        self.filename = filename
        self.name, _ = os.path.splitext(os.path.basename(self.filename))
        self.init = None
        self.dependencies = set()
        self.dispatcher = dispatcher
        self.module = None
        self.state = self.UNLOADED
        self.metadata = None
        self.registers = {
            'attach_hooks': [],
            'event_handlers': [],
            'event_sources': [],
            'event_types': [],
            'hooks': [],
            'providers': [],
            'resources': [],
            'schema_definitions': [],
            'task_handlers': [],
            'debug': []
        }

    def assign_module(self, module):
        if not hasattr(module, '_init'):
            raise Exception('Invalid plugin module, _init method not found')

        if hasattr(module, '_depends'):
            self.dependencies = set(module._depends())

        if hasattr(module, '_metadata'):
            self.metadata = module._metadata()

        self.module = module

    def push_status(self, message):
        push_status('{0}: {1}'.format(self.name, message))

    def attach_hook(self, name, func):
        self.dispatcher.attach_hook(name, func)
        self.registers['attach_hooks'].append((name, func))

    def detach_hook(self, name, func):
        self.dispatcher.detach_hook(name, func)
        self.registers['attach_hooks'].remove((name, func))

    def load(self):
        try:
            self.module._init(self.dispatcher, self)
            self.state = self.LOADED
            self.dispatcher.dispatch_event('server.plugin.initialized', {"name": self.name})
            with contextlib.suppress(BaseException):
                push_status('Plugin loaded: {0}'.format(self.name))
        except Exception as err:
            self.dispatcher.logger.exception('Plugin %s exception', self.filename)
            self.dispatcher.report_error('Cannot initalize plugin {0}'.format(self.filename), err)
            raise RuntimeError('Cannot load plugin {0}: {1}'.format(self.filename, str(err)))

    def register_event_handler(self, name, handler):
        self.dispatcher.register_event_handler(name, handler)
        self.registers['event_handlers'].append((name, handler))
        return handler

    def unregister_event_handler(self, name, handler):
        self.dispatcher.unregister_event_handler(name, handler)
        self.registers['event_handlers'].remove((name, handler))
        return handler

    def register_event_source(self, name, clazz):
        self.dispatcher.register_event_source(name, clazz)
        self.registers['event_sources'].append(name)

    def register_event_type(self, name, source=None, schema=None):
        self.dispatcher.register_event_type(name, source, schema)
        self.registers['event_types'].append(name)

    def unregister_event_type(self, name):
        self.dispatcher.unregister_event_type(name)
        self.registers['event_types'].remove(name)

    def register_task_handler(self, name, clazz):
        self.dispatcher.register_task_handler(name, clazz)
        self.registers['task_handlers'].append(name)

    def register_task_alias(self, name, name2):
        self.dispatcher.register_task_alias(name, name2)
        self.registers['task_handlers'].append(name)

    def unregister_task_handler(self, name):
        self.dispatcher.unregister_task_handler(name)
        self.registers['task_handlers'].remove(name)

    def register_provider(self, name, clazz):
        self.dispatcher.register_provider(name, clazz)
        self.registers['providers'].append(name)

    def unregister_provider(self, name):
        self.dispatcher.unregister_provider(name)
        self.registers['providers'].remove(name)

    def register_schema_definition(self, name, definition):
        self.dispatcher.register_schema_definition(name, definition)
        self.registers['schema_definitions'].append(name)

    def unregister_schema_definition(self, name):
        self.dispatcher.unregister_schema_definition(name)
        self.registers['schema_definitions'].remove(name)

    def register_resource(self, res, parents=None):
        self.dispatcher.register_resource(res, parents)
        self.registers['resources'].append((res, parents))

    def unregister_resource(self, res):
        self.dispatcher.unregister_resource(res)
        self.registers['resources'].remove(res)

    def register_hook(self, name):
        self.dispatcher.register_hook(name)
        self.registers['hooks'].append(name)

    def unregister_hook(self, name):
        self.dispatcher.unregister_hook(name)
        self.registers['hooks'].remove(name)

    def register_debug_hook(self, func):
        self.registers['debug'].append(func)

    def unload(self):
        if hasattr(self.module, '_cleanup'):
            self.module._cleanup(self.dispatcher, self)

        self.dispatcher.logger.debug('Unregistering plugin {0} types'.format(
            self.filename
        ))

        for name, handler in list(self.registers['event_handlers']):
            self.unregister_event_handler(name, handler)

        #for name in self.registers['event_sources']:
        #    pass

        for name in list(self.registers['event_types']):
            self.unregister_event_type(name)

        for name, func in list(self.registers['attach_hooks']):
            self.detach_hook(name, func)

        for name in list(self.registers['hooks']):
            self.unregister_hook(name)

        for name in list(self.registers['providers']):
            self.unregister_provider(name)

        for name in list(self.registers['resources']):
            self.unregister_resource(name)

        for name in list(self.registers['schema_definitions']):
            self.unregister_schema_definition(name)

        for name in list(self.registers['task_handlers']):
            self.unregister_task_handler(name)

        self.state = self.UNLOADED

    def reload(self):
        self.unload()
        self.load()


class EventType(object):
    __slots__ = ('name', 'source', 'schema', 'refcount', 'lock', 'logger')

    def __init__(self, name, source=None, schema=None):
        self.name = name
        self.source = source
        self.schema = schema
        self.refcount = 0
        self.lock = RLock()
        self.logger = logging.getLogger('EventType:{0}'.format(name))

    def incref(self):
        with self.lock:
            if self.refcount == 0 and self.source:
                self.source.enable(self.name)
                self.logger.log(TRACE, 'Enabling event source: {0}'.format(self.name))

            self.refcount += 1

    def decref(self):
        with self.lock:
            # lets not go below 0!!!
            if self.refcount > 0:
                self.refcount -= 1
            elif self.refcount < 0:
                # Ok so something is messed up
                # fix it by going to 0
                self.refcount = 0
                self.logger.error("{0}'s refcount was below zero and was being decreased".format(self.name))
                self.logger.error("Traceback: {0}".format(traceback.format_stack()))
                return
            elif self.refcount == 0:
                self.logger.error("Cannot decrease {0}'s refcount below zero!".format(self.name))
                self.logger.error("Traceback: {0}".format(traceback.format_stack()))
                return

            if self.refcount == 0 and self.source:
                self.source.disable(self.name)
                self.logger.log(TRACE, 'Disabling event source: {0}'.format(self.name))


class Dispatcher(object):
    def __init__(self, *args, **kwargs):
        self.started_at = None
        self.plugin_dirs = []
        self.event_types = {}
        self.event_sources = {}
        self.event_handlers = {}
        self.hooks = {}
        self.plugins = {}
        self.threads = []
        self.queues = {}
        self.providers = {}
        self.tasks = {}
        self.task_hooks = {}
        self.resource_graph = ResourceGraph()
        self.resource_trackers = []
        self.logger = logging.getLogger('Main')
        self.token_store = TokenStore(self)
        self.event_delivery_lock = RLock()
        self.rpc = None
        self.balancer = None
        self.datastore = None
        self.datastore_log = None
        self.configfile = None
        self.configstore = None
        self.config = None
        self.auth = None
        self.features = set(FEATURES)
        self.ws_servers = []
        self.http_servers = []
        self.pidfile = None
        self.use_tls = False
        self.certfile = None
        self.keyfile = None
        self.ready = Event()
        self.port = 0
        self.file_ws_connectios = None
        self.logdb_proc = None
        self.logdb_ready = False
        self.threadpool = ThreadPool(20)
        self.load_disabled_plugins = kwargs.get('load_disabled', False)

    def init(self):
        self.logger.info('Initializing')

        self.datastore = get_datastore(self.configfile)
        self.configstore = ConfigStore(self.datastore)

        self.logger.info('Connected to datastore')

        self.balancer = Balancer(self)
        self.auth = PasswordAuthenticator(self)
        self.rpc = DispatcherRpcContext(self)
        self.rpc.streaming_enabled = True
        self.rpc.streaming_burst = self.configstore.get('middleware.streaming_burst_size') or 1
        register_general_purpose_schemas(self)

        self.rpc.register_service('management', ManagementService)
        self.rpc.register_service('debug', DebugService)
        self.rpc.register_service('event', EventService)
        self.rpc.register_service('task', TaskService)
        self.rpc.register_service('plugin', PluginService)
        self.rpc.register_service('shell', ShellService)
        self.rpc.register_service('lock', LockService)

        self.register_event_type('server.client_connected')
        self.register_event_type('server.client_transport_connected')
        self.register_event_type('server.client_disconnected')
        self.register_event_type('server.client_login')
        self.register_event_type('server.client_logout')
        self.register_event_type('server.service_login')
        self.register_event_type('server.service_logout')
        self.register_event_type('server.plugin.load_error')
        self.register_event_type('server.plugin.loaded')
        self.register_event_type('server.ready')
        self.register_event_type('server.shutdown')
        self.register_event_type('server.schema_document_changed')

    def start(self):
        self.started_at = time.time()
        self.balancer.start()
        self.ready.set()
        self.logger.info('Server is ready')
        self.dispatch_event('server.ready', {
            'description': 'Server is completely loaded and ready to use.',
        })

        # serviced check-in
        checkin()

    def read_config_file(self, file):
        try:
            f = open(file, 'r')
            data = json.load(f)
            f.close()
        except (IOError, ValueError):
            raise

        self.configfile = file
        self.config = data
        self.plugin_dirs = data['dispatcher']['plugin-dirs']
        self.pidfile = data['dispatcher']['pidfile']

        if 'tls' in data['dispatcher'] and data['dispatcher']['tls']:
            self.use_tls = True
            self.certfile = data['dispatcher']['tls-certificate']
            self.keyfile = data['dispatcher']['tls-keyfile']

    def discover_plugins(self):
        for dir in self.plugin_dirs:
            self.logger.debug("Searching for plugins in %s", dir)
            self.__discover_plugin_dir(dir)

    def load_plugins(self):
        loaded = set()
        toload = self.plugins.copy()
        loadlist = []

        while len(toload) > 0:
            found = False
            for name, plugin in list(toload.items()):
                if len(plugin.dependencies - loaded) == 0:
                    found = True
                    loadlist.append(plugin)
                    loaded.add(name)
                    del toload[name]

            if not found:
                self.logger.warning(
                    "Could not load following plugins due to circular dependencies: {0}".format(', '.join(toload)))
                break

        for i in loadlist:
            try:
                i.load()
            except RuntimeError as err:
                self.logger.exception("Error initializing plugin %s: %s", i.filename, err.args)

    def reload_plugins(self):
        # Reload existing modules
        for i in list(self.plugins.values()):
            i.reload()

        # And look for new ones
        self.discover_plugins()

    def unload_plugins(self):
        # Generate a list of inverse plugin dependency
        required_by = {}
        for name, plugin in list(self.plugins.items()):
            if name not in required_by:
                required_by[name] = set()
            for dep in plugin.dependencies:
                if dep not in required_by:
                    required_by[dep] = set()
                required_by[dep].add(name)

        # Get a sequential list of plugins to unload
        # Plugins that no other depend on come first
        unloadlist = []
        while len(required_by) > 0:
            found = False
            for name, deps in list(required_by.items()):
                if len(deps) > 0:
                    continue

                # Remove the plugin from the list that it depends on
                plugin = self.plugins.get(name)
                for dep in plugin.dependencies:
                    if dep in required_by and name in required_by[dep]:
                        required_by[dep].remove(name)
                unloadlist.append(plugin)

                del required_by[name]
                found = True
                break

            if not found:
                self.logger.warning(
                    "Could not unload following plugins due to circular "
                    "dependencies: {0}".format(required_by)
                )
                break

        for i in unloadlist:
            try:
                i.unload()
            except BaseException:
                self.logger.warning(
                    "Error unloading plugin {0}".format(i.filename),
                    exc_info=True
                )

    def __discover_plugin_dir(self, dir):
        for root, dirnames, filenames in os.walk(dir):
            # Skipping disabled plugins, unles explicitly informed to load them
            if not self.load_disabled_plugins and os.path.basename(root) == 'disabled':
                continue

            for i in fnmatch.filter(filenames, '*.py') + fnmatch.filter(filenames, '*.so'):
                self.__try_load_plugin(os.path.join(dir, os.path.join(root, i)))

    def __try_load_plugin(self, path):
        if path in self.plugins:
            return

        self.logger.debug("Loading plugin from %s", path)
        try:
            name, _ = os.path.splitext(os.path.basename(path))
            plugin = Plugin(self, path)
            plugin.assign_module(load_module_from_file(name, path))
            self.plugins[name] = plugin
        except Exception as err:
            self.logger.exception("Cannot load plugin from %s", path)
            self.report_error('Cannot load plugin from {0}'.format(path), err)
            self.dispatch_event("server.plugin.load_error", {"name": os.path.basename(path)})
            return

        self.dispatch_event("server.plugin.loaded", {"name": os.path.basename(path)})

    def set_syslog_level(self, level):
        if level == 'TRACE':
            log_level = TRACE
        else:
            log_level = getattr(logging, level, None)

        if not log_level:
            raise RpcException(errno.EINVAL, 'Invalid logging level {0} selected'.format(level))
        logging.root.setLevel(log_level)

    def dispatch_event(self, name, args):
        self.logger.log(TRACE, 'Dispatching event: name={0} args={1}'.format(name, args))
        with self.event_delivery_lock:
            # If there's no timestamp, assume event fired right now
            args.setdefault('timestamp', datetime.datetime.utcnow())

            for srv in self.ws_servers:
                for conn in srv.connections:
                    conn.outgoing_events.put((name, args))

        for h in self.event_handlers.get(name, []):
            def wrapper(handler, name):
                try:
                    self.logger.log(TRACE, 'Calling event handler {0} for event {1}'.format(handler, name))
                    handler(args)
                except BaseException:
                    self.logger.exception('Event handler for event %s failed', name)

            greenlet = gevent.spawn(wrapper, h, name)
            if getattr(h, 'sync', False):
                greenlet.join()

    def emit_event(self, name, args):
        return self.dispatch_event(name, args)

    def call_sync(self, name, *args, **kwargs):
        return self.rpc.call_sync(name, *args, **kwargs)

    def call_async(self, name, callback, *args, **kwargs):
        def call(n, c, *a):
            try:
                c(self.rpc.call_sync(n, *a))
            except RpcException as err:
                c(err)

        if callable(callback):
            gevent.spawn(call, name, callback, *args)

    def call_task_sync(self, name, *args):
        t = self.balancer.run_subtask(None, name, args)
        self.balancer.join_subtasks(t)
        return t.result

    def submit_task(self, name, *args):
        self.balancer.run_subtask(None, name, args)

    def verify_subtask(self, *args, **kwargs):
        return self.balancer.verify_subtask(*args, **kwargs)

    def register_event_handler(self, name, handler):
        self.event_handlers.setdefault(name, [])
        self.event_handlers[name].append(handler)

        for en, ev in self.event_types.items():
            if en == name:
                ev.incref()

        return handler

    def unregister_event_handler(self, name, handler):
        self.event_handlers[name].remove(handler)
        for en, ev in self.event_types.items():
            if en == name:
                ev.decref()

    def register_event_handler_once(self, name, handler):
        lock = RLock()

        def doit(args):
            with lock:
                handler(args)
                self.unregister_event_handler(name, doit)

        self.register_event_handler(name, doit)

    def register_event_source(self, name, clazz):
        self.logger.debug("New event source: %s", name)
        self.event_sources[name] = clazz

        source = clazz(self)
        greenlet = gevent.spawn(source.run)
        self.threads.append(greenlet)

    def register_event_type(self, name, source=None, schema=None):
        self.event_types[name] = EventType(name, source, schema)
        self.dispatch_event('server.event.added', {'name': name})

    def unregister_event_type(self, name):
        del self.event_types[name]
        self.dispatch_event('server.event.removed', {'name': name})

    def register_task_handler(self, name, clazz):
        self.logger.debug("New task handler: {0}".format(name))
        self.tasks[name] = clazz

    def register_task_alias(self, name, name2):
        self.logger.debug("New task alias: {0} -> {1}".format(name, name2))
        self.tasks[name] = self.tasks[name2]

    def unregister_task_handler(self, name):
        del self.tasks[name]

    def register_task_hook(self, hook, name, condition=None):
        task_name, hook_name = hook.split(':')
        hooks = self.task_hooks.setdefault(task_name, {})
        hooklist = hooks.setdefault(hook_name, {})
        hooklist[name] = {
            'condition': condition
        }

    def unregister_task_hook(self, hook, name):
        task_name, hook_name = hook.split(':')
        hooks = self.task_hooks.get(task_name, {})
        hooklist = hooks.get(hook_name, {})
        with contextlib.suppress(ValueError):
            hooklist.pop(name)

    def register_provider(self, name, clazz):
        self.logger.debug("New provider: %s", name)
        self.providers[name] = clazz
        self.rpc.register_service(name, clazz)

    def unregister_provider(self, name):
        self.logger.debug("Unregistering provider: %s", name)
        self.rpc.unregister_service(name)
        del self.providers[name]

    def register_schema_definition(self, name, definition):
        self.rpc.register_schema_definition(name, definition)
        if self.ready:
            def emit_changed_event():
                self.dispatch_event('server.schema_document_changed', {
                    'hash': self.call_sync('discovery.get_schema_hash')
                })

            gevent.spawn(emit_changed_event)

    def unregister_schema_definition(self, name):
        self.rpc.unregister_schema_definition(name)

    def require_collection(self, collection, pkey_type='uuid', **kwargs):
        if not self.datastore.collection_exists(collection):
            self.datastore.collection_create(collection, pkey_type, kwargs)

    def register_resource(self, res, parents=None, children=None):
        self.logger.debug('Resource added: {0}'.format(res.name))
        self.resource_graph.add_resource(res, parents, children)

    def update_resource(self, name, new_parents, new_children=None):
        self.logger.log(TRACE, 'Resource updated: {0}, new parents: {1}'.format(name, ', '.join(new_parents)))
        self.resource_graph.update_resource(name, new_parents, new_children)

    def rename_resource(self, oldname, newname):
        self.logger.log(TRACE, 'Resource renamed: {0} ->{1}'.format(oldname, newname))
        self.resource_graph.rename_resource(oldname, newname)

    def unregister_resource(self, name):
        self.logger.debug('Resource removed: {0}'.format(name))
        self.resource_graph.remove_resource(name)

    def unregister_resources(self, names):
        if names:
            self.logger.debug('Resources removed: {0}'.format(', '.join(names)))
            self.resource_graph.remove_resources(names)

    def resource_exists(self, name):
        return self.resource_graph.get_resource(name) is not None

    def track_resources(self, query_call, changed_event, name_callback, parents_callback, children_callback=None):
        self.resource_trackers.append(ResourceTracker(
            self,
            query_call,
            changed_event,
            name_callback,
            parents_callback,
            children_callback
        ))

    def register_hook(self, name):
        self.hooks.setdefault(name, [])

    def unregister_hook(self, name):
        del self.hooks[name]

    def attach_hook(self, name, func):
        self.register_hook(name)
        self.hooks[name].append(func)
        return func

    def detach_hook(self, name, func):
        self.hooks[name].remove(func)

    def run_hook(self, name, *args):
        for h in self.hooks[name]:
            try:
                if not h(*args):
                    return False
            except BaseException as err:
                self.report_error('Hook for {0} with args {1} failed'.format(name, args), err)
                return False

        return True

    def test_or_wait_for_event(self, event, match_fn, initial_condition_fn, timeout=None):
        done = Event()
        with self.event_delivery_lock:
            if initial_condition_fn():
                return

            def handler(args):
                if match_fn(args):
                    self.logger.debug("Test or wait condition satisfied for event {0}".format(event))
                    done.set()

            self.register_event_handler(event, handler)

        done.wait(timeout=timeout)
        self.unregister_event_handler(event, handler)

    def exec_and_wait_for_event(self, event, match_fn, fn, timeout=None):
        done = Event()
        with self.event_delivery_lock:
            fn()

            def handler(args):
                if match_fn(args):
                    self.logger.debug("Exec and wait condition satisfied for event {0}".format(event))
                    done.set()

            self.register_event_handler(event, handler)

        done.wait(timeout=timeout)
        self.unregister_event_handler(event, handler)

    def threaded(self, fn, *args, **kwargs):
        return self.threadpool.apply(fn, args, kwargs)

    def get_lock(self, name):
        self.call_sync('lock.init', name)
        return ServerLockProxy(self, name)

    def report_error(self, message, exception):
        self.logger.debug('Reporting error: {0} exception:{1}'.format(message, exception))

        try:
            os.makedirs('/var/tmp/crash', exist_ok=True)
        except:
            # at least we tried
            return

        report = {
            'timestamp': str(datetime.datetime.utcnow()),
            'type': 'exception',
            'application': 'dispatcher',
            'title': message,
            'exception': serialize_exception(exception, getattr(exception, 'stacktrace', None))
        }

        try:
            with tempfile.NamedTemporaryFile(dir='/var/tmp/crash', mode='w', suffix='.json', prefix='report-', delete=False) as f:
                json.dump(report, f, indent=4)
        except BaseException as err:
            self.logger.debug('Cannot write error report: {0}'.format(str(err)))
            pass

    def die(self):
        self.logger.warning('Exiting from "die" command')
        self.dispatch_event('server.shutdown', {
            'description': 'Server is shutting down.',
        })

        self.balancer.dispose_executors()
        self.logger.warning('Unloading plugins')
        self.unload_plugins()

        self.logger.info('Killing server threads')
        gevent.killall(self.threads)

        self.logger.debug('Closing datastore connections')
        self.datastore.close()
        self.stop_logdb()

        self.logger.debug('Really exiting now')
        sys.exit(0)

    def start_logdb(self):
        self.logdb_proc = subprocess.Popen(['/usr/local/sbin/dswatch', 'datastore-log'], preexec_fn=os.setpgrp)
        self.datastore_log = get_datastore(self.configfile, log=True)
        self.emit_event('server.logdb_ready', {})

    def migrate_logdb(self):
        FACTORY_FILE = '/usr/local/share/datastore/factory-log.json'
        MIGRATIONS_DIR = '/usr/local/share/datastore/migrations'

        self.logger.info('Migrating log database')

        try:
            with open(FACTORY_FILE, 'r') as fd:
                dump = json.load(fd)
                migrate_db(self.datastore_log, dump, MIGRATIONS_DIR, ['log'], True)
        except IOError as err:
            self.logger.warning('Cannot open factory.json: {0}'.format(str(err)))
        except ValueError as err:
            self.logger.warning('Cannot parse factory.json: {0}'.format(str(err)))
        except MigrationException as err:
            self.logger.warning('Log database migration failed: {0}'.format(str(err)))

    def stop_logdb(self):
        if self.logdb_proc:
            self.logdb_proc.terminate()
            self.logdb_proc.wait()
            self.logger.debug('Log database server terminated with exit code {0}'.format(self.logdb_proc.returncode))


class DispatcherRpcContext(RpcContext):
    def __init__(self, dispatcher):
        super(DispatcherRpcContext, self).__init__()
        self.dispatcher = dispatcher

    def call_sync(self, name, *args, **kwargs):
        no_copy = kwargs.pop('no_copy', False)

        def unpack_chunk(it):
            for chunk in it:
                for item in chunk:
                    yield item if no_copy else copy.deepcopy(item)

        result = self.dispatch_call(name, list(args), streaming=True, validation=False)
        if hasattr(result, '__next__'):
            return unpack_chunk(result)

        return result if no_copy else copy.deepcopy(result)


class DispatcherConnection(ServerConnection):
    def __init__(self, parent):
        super(DispatcherConnection, self).__init__(parent)
        self.dispatcher = parent.context
        self.rpc = parent.context.rpc
        self.credentials = None
        self.proxy_address = None
        self.server_pending_calls = {}
        self.client_pending_calls = {}
        self.outgoing_events = Queue()
        self.enabled_features = set()
        self.resource = None
        self.user = None
        self.session_id = None
        self.token = None
        self.event_masks = set()
        self.event_subscription_lock = RLock()
        self.has_external_transport = False
        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    def client_address(self):
        if self.proxy_address:
            return self.proxy_address

        return ','.join(str(i) for i in self.transport.client_address[:2])

    def __getstate__(self):
        return {
            'resource': self.resource,
            'user': self.user.name if self.user else None,
            'address': self.client_address
        }

    def __event_worker(self):
        for name, args in self.outgoing_events:
            self.emit_event(name, args)

    def log(self, level, msg):
        self.logger.log(level, '[{0}] {1}'.format(self.client_address, msg))

    def trace(self, msg):
        self.logger.log(TRACE, '[{0}] {1}'.format(self.client_address, msg))

    def on_open(self):
        super(DispatcherConnection, self).on_open()
        gevent.spawn(self.__event_worker)
        self.trace('Connected')
        self.dispatcher.dispatch_event('server.client_connected', {
            'address': self.client_address,
            'description': "Client {0} connected".format(self.client_address)
        })

    def on_close(self, reason):
        super(DispatcherConnection, self).on_close(reason)
        self.trace('Disconnected')

        if self.user:
            self.close_session()
            self.user = None

        for mask in set(self.event_masks):
            for name, ev in list(self.dispatcher.event_types.items()):
                if match_event(name, mask):
                    ev.decref()

            self.event_masks.remove(mask)

        self.outgoing_events.put(StopIteration)
        self.dispatcher.dispatch_event('server.client_disconnected', {
            'address': self.client_address,
            'description': "Client {0} disconnected".format(self.client_address)
        })

    def on_transport_setup(self, id, client_address):
        self.has_external_transport = True
        self.proxy_address = ','.join(str(i) for i in client_address)

        self.trace('Client transport layer set up - client {0} proxied via {1}'.format(
            self.client_address,
            self.proxy_address
        ))

        self.dispatcher.dispatch_event('server.client_transport_connected', {
            'old_address': self.proxy_address,
            'new_address': self.client_address,
            'description': "Client transport layer set up - client {0} proxied via {1}".format(
                self.client_address,
                self.proxy_address
            )
        })

    def on_events_subscribe(self, id, event_masks):
        if not isinstance(event_masks, list):
            return

        if self.user is None:
            return

        self.trace('Events subscribe: masks={0}'.format(event_masks))

        # Keep session alive
        if self.token:
            self.dispatcher.token_store.keepalive_token(self.token)

        with self.event_subscription_lock:
            # Increment reference count for any newly subscribed event
            for mask in set.difference(set(event_masks), self.event_masks):
                for name, ev in list(self.dispatcher.event_types.items()):
                    if match_event(name, mask):
                        ev.incref()

            self.event_masks = set.union(self.event_masks, set(event_masks))

    def on_events_unsubscribe(self, id, event_masks):
        if not isinstance(event_masks, list):
            return

        if self.user is None:
            return

        self.trace('Events unsubscribe: masks={0}'.format(event_masks))

        # Keep session alive
        if self.token:
            self.dispatcher.token_store.keepalive_token(self.token)

        with self.event_subscription_lock:
            # Decrement reference count for any newly unsubscribed event
            intersecting_unsubscribe_events = set.intersection(set(event_masks), self.event_masks)
            for mask in intersecting_unsubscribe_events:
                for name, ev in list(self.dispatcher.event_types.items()):
                    if match_event(name, mask):
                        ev.decref()

            self.event_masks = set.difference(self.event_masks, intersecting_unsubscribe_events)

    def on_events_event(self, id, data):
        if self.user is None:
            return

        self.trace('New event: name={0} args={1}'.format(data['name'], data['args']))

        # Keep session alive
        if self.token:
            self.dispatcher.token_store.keepalive_token(self.token)

        self.dispatcher.dispatch_event(data['name'], data['args'])

    def on_events_event_burst(self, id, data):
        if self.user is None:
            return

        # Keep session alive
        if self.token:
            self.dispatcher.token_store.keepalive_token(self.token)

        if 'events' not in data:
            return

        for i in data['events']:
            self.dispatcher.dispatch_event(i['name'], i['args'])

    def on_rpc_auth_service(self, id, data):
        client_addr, _ = self.client_address.split(',', 2)
        service_name = data['name']

        self.trace('Service auth request: service={0}'.format(service_name))

        if client_addr not in ('127.0.0.1', '::1', 'unix') and not self.has_external_transport:
            return

        self.send_response(id, [])
        self.user = self.dispatcher.auth.get_service(service_name)
        self.open_session()
        self.dispatcher.dispatch_event('server.service_login', {
            'address': self.client_address,
            'name': service_name,
            'description': "Service {0} logged in".format(service_name)
        })

    def on_rpc_auth_token(self, id, data):
        token = data['token']
        resource = data.get('resource', None)
        lifetime = self.dispatcher.configstore.get("middleware.token_lifetime")

        self.trace('Token auth request: token={0}'.format(token))

        token = self.dispatcher.token_store.lookup_token(token)
        if not token:
            self.emit_rpc_error(id, errno.EACCES, "Incorrect or expired token")
            return

        self.user = token.user
        self.open_session()

        self.token = self.dispatcher.token_store.issue_token(
            Token(
                user=self.user,
                lifetime=lifetime,
                session_id=self.session_id,
                revocation_function=self.logout
            )
        )

        self.send_response(id, [self.token, lifetime, self.user.name])
        self.dispatcher.dispatch_event('server.client_loggin', {
            'address': self.client_address,
            'resource': resource,
            'username': self.user.name,
            'description': "Client {0} logged in".format(self.user.name)
        })

    def on_rpc_auth(self, id, data):
        username = data['username']
        password = data['password']
        lifetime = self.dispatcher.configstore.get("middleware.token_lifetime")
        check_password = data.get('check_password', False)
        client_addr, client_port = self.client_address.split(',', 2)
        self.resource = data.get('resource', None)

        self.trace('User auth request: username={0} password={1} resource={2}'.format(
            username,
            password,
            self.resource
        ))

        user = self.dispatcher.auth.get_user(username)
        if user is None:
            self.trace('User {0} not found'.format(username))
            self.emit_rpc_error(id, errno.EACCES, "Incorrect username or password")
            return

        if (client_addr in ('127.0.0.1', '::1', 'unix') or self.has_external_transport) and not check_password:
            # If client is connecting from localhost, omit checking password
            # and instead verify his username using sockstat(1). Also make
            # token lifetime None for such users (as we do not want their
            # sessions to timeout)
            # If client is connecting using transport layer other than raw ws
            # authentication part is held by transport layer itself so we do not
            # check password correctness but be aware such users sessions will timeout.
            if not self.has_external_transport and client_addr != 'unix':
                if not user.check_local(client_addr, int(client_port), self.dispatcher.port):
                    self.emit_rpc_error(id, errno.EACCES, "Incorrect username or password")
                    return

                lifetime = None
        else:
            if not user.check_password(password):
                self.trace('Incorrect password for user {0}'.format(username))
                self.emit_rpc_error(id, errno.EACCES, "Incorrect username or password")
                return

        if not user.has_role('wheel'):
            self.trace('User {0} not in group wheel'.format(username))
            self.emit_rpc_error(id, errno.EACCES, "Not authorized")
            return

        if client_addr == 'unix':
            lifetime = None

        self.user = user
        self.open_session()
        self.token = self.dispatcher.token_store.issue_token(Token(
            user=user,
            lifetime=lifetime,
            session_id=self.session_id,
            revocation_function=self.logout
        ))

        self.send_response(id, [self.token, lifetime, self.user.name])
        self.dispatcher.dispatch_event('server.client_login', {
            'address': self.client_address,
            'username': username,
            'description': "Client {0} logged in".format(username)
        })

    def on_rpc_call(self, id, data):
        # Keep session alive
        if self.token:
            self.dispatcher.token_store.keepalive_token(self.token)

        super(DispatcherConnection, self).on_rpc_call(id, data)

    def open_session(self):
        if self.dispatcher.logdb_ready:
            try:
                self.session_id = self.dispatcher.datastore_log.insert('sessions', {
                    'started_at': datetime.datetime.utcnow(),
                    'address': self.client_address,
                    'resource': self.resource,
                    'active': True,
                    'username': self.user.name
                })
            except:
                pass

        self.dispatcher.dispatch_event('session.changed', {
            'operation': 'create',
            'ids': [self.session_id]
        })

    def close_session(self):
        if self.session_id and self.dispatcher.logdb_ready:
            try:
                session = self.dispatcher.datastore_log.get_by_id('sessions', self.session_id)
                session['active'] = False
                session['ended_at'] = datetime.datetime.utcnow()
                self.dispatcher.datastore_log.update('sessions', self.session_id, session)
                self.dispatcher.dispatch_event('session.changed', {
                    'operation': 'update',
                    'ids': [self.session_id]
                })
            except:
                pass

        if isinstance(self.user, User):
            self.dispatcher.dispatch_event('server.client_logout', {
                'address': self.client_address,
                'username': self.user.name,
                'description': "Client {0} logged out".format(self.user.name)
            })

        elif isinstance(self.user, Service):
            self.dispatcher.dispatch_event('server.service_logout', {
                'address': self.client_address,
                'name': self.user.name,
                'description': "Client {0} logged out".format(self.user.name)
            })

    def broadcast_event(self, event, args):
        for i in self.parent.connections:
            i.emit_event(event, args)

    def enable_feature(self, feature):
        if feature not in self.dispatcher.features:
            raise ValueError('Invalid feature')

        self.log(TRACE, 'Enabling feature {0}'.format(feature))

        if feature == 'strict_validation':
            self.dispatcher.rpc.strict_validation = True

        if feature == 'streaming_responses':
            self.streaming = True

        self.enabled_features.add(feature)

    def logout(self, token_store, token, token_id):
        try:
            self.send('events', 'logout', {
                "reason": token.revocation_reason
            })

            # Delete the token at logout since otherwise the reconnect will just log the session back in
            token_store.revoke_token(token_id)
            self.transport.close()
        except WebSocketError as werr:
            # This error usually implies that the socket is dead so just log it and move on
            self.dispatcher.logger.debug(
                'Tried to logout Websocket Connection and the ' +
                'following error occured {0}'.format(str(werr)))

    def emit_event(self, event, args):
        for i in list(self.event_masks):
            if not match_event(event, i):
                continue

            self.send_event(event, args)

    def emit_rpc_call(self, id, method, args):
        return self.send_call(id, method, args)

    def emit_rpc_error(self, id, code, message, extra=None):
        return self.send_error(id, code, message, extra)


class ShellConnection(WebSocketApplication, EventEmitter):
    BUFSIZE = 1024

    def __init__(self, ws, parent):
        super(ShellConnection, self).__init__(ws)
        self.dispatcher = parent.context
        self.logger = logging.getLogger('ShellConnection')
        self.token = None
        self.authenticated = False
        self.master = None
        self.slave = None
        self.closed = Event()
        self.pid = None
        self.inq = Queue()

    def worker(self, user, shell, w, h):
        self.logger.info('Opening shell %s...', shell)
        env = os.environ.copy()
        env['TERM'] = 'xterm'
        env['LANG'] = 'en_US.UTF-8'
        env['PATH'] = '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin'

        try:
            uinfo = self.dispatcher.call_sync('dscached.account.getpwnam', user)
        except RpcException:
            self.ws.close()
            return

        def read_worker():
            while True:
                data = tp_read(self.master, self.BUFSIZE)
                if not data:
                    break

                self.ws.send(data)

            self.ws.close()

        def write_worker():
            for i in self.inq:
                tp_write(self.master, i.encode('utf-8'))

        def callback(watcher):
            watcher.stop()
            self.closed.set()

        def resize(width, height):
            payload = struct.pack('HHHH', height, width, 0, 0)
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, payload)
            os.kill(self.pid, signal.SIGWINCH)

        self.pid, self.master = forkpty_and_watch(callback)
        wr = gevent.spawn(write_worker)
        rd = gevent.spawn(read_worker)

        if self.pid == 0:
            os.seteuid(uinfo['uid'])
            os.execve('/bin/sh', ['sh', '-c', shell], env)

        resize(w, h)
        self.logger.info('Shell %s spawned as PID %d', shell, self.pid)
        self.token.resize = resize
        self.closed.wait()
        gevent.joinall([rd, wr])

    def on_open(self, *args, **kwargs):
        pass

    def on_close(self, *args, **kwargs):
        self.inq.put(StopIteration)
        self.logger.info('Terminating shell PID %d', self.pid)
        try:
            os.kill(self.pid, signal.SIGTERM)
        except OSError:
            pass

        os.close(self.master)

    def on_message(self, message, *args, **kwargs):
        if message is None:
            return

        if not self.authenticated:
            if type(message) is bytes:
                message = message.decode('utf-8')

            message = loads(message)

            if type(message) is not dict:
                return

            if 'token' not in message:
                return

            self.token = self.dispatcher.token_store.lookup_token(message['token'])
            if not self.token:
                self.ws.send(dumps({'status': 'error'}))
                return

            self.authenticated = True
            self.ws.send(dumps({'status': 'ok'}))
            gevent.spawn(self.worker, self.token.user.name, self.token.shell, self.token.width, self.token.height)
            return

        for i in message:
            if i == '\r':
                i = '\n'
            self.inq.put(i)

        self.dispatcher.token_store.keepalive_token(self.token)


class FileConnection(WebSocketApplication, EventEmitter):
    BUFSIZE = 1024

    def __init__(self, ws, parent):
        super(FileConnection, self).__init__(ws)
        self.dispatcher = parent.context
        self.token = None
        self.authenticated = False
        self.bytes_done = None
        self.bytes_total = None
        self.done = Event()
        self.inq = Queue()
        self.logger = logging.getLogger('FileConnection')

    def worker(self, file, direction, size=None):
        try:
            self.bytes_done = 0
            if self.token.direction == "download":
                while True:
                    data = file.read(self.BUFSIZE)
                    if data == b'':
                        break
                    self.bytes_done += len(data)
                    self.ws.send(data)
                    # issue keepalive
                    self.dispatcher.token_store.keepalive_token(self.token)
            else:
                for i in self.inq:
                    if i == b'':
                        break

                    i = memoryview(i)
                    num_written = 0
                    while num_written < len(i):
                        done = file.write(i[num_written:])
                        if done == 0:
                            # close everything
                            return
                        self.bytes_done += done
                        num_written += done
                    # issue keepalive
                    self.dispatcher.token_store.keepalive_token(self.token)
        finally:
            file.close()
            self.done.set()
            self.ws.close()

    def on_open(self, *args, **kwargs):
        self.logger.trace(
            "FileConnection Opened with args: {0} and kwargs: {1}".format(args, kwargs)
        )

    def on_close(self, *args, **kwargs):
        self.inq.put(StopIteration)
        self.logger.trace(
            "File {0} Closed for file {1}".format(self.token.direction, self.token.name)
        )
        self.dispatcher.token_store.delete_token(self.token)

    def on_message(self, message, *args, **kwargs):
        if message is None:
            return

        if not self.authenticated:
            message = loads(message.decode('utf-8') if type(message) is bytes else message)
            if type(message) is not dict or 'token' not in message:
                return

            self.token = self.dispatcher.token_store.lookup_token(message['token'])
            # issue keepalive
            self.dispatcher.token_store.keepalive_token(self.token)
            self.authenticated = True
            self.bytes_total = self.token.size

            gevent.spawn(self.worker, self.token.file, self.token.direction, self.token.size)
            # self.dispatcher.file_ws_connectios[message["token"]] = self
            # self.dispatcher.balancer.submit(
            #     'file.{0}'.format(self.token.direction), [self], self.token.user)
            self.ws.send(dumps({'status': 'ok'}))
        elif type(message) is str:
            try:
                message = loads(message)
                if message.get('done'):
                    self.inq.put(b'')
            except:
                pass
        else:
            # Normal upload data
            self.inq.put(message)


# Custom handler for enabling downloading of files
class DownloadRequestHandler(object):

    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.token = None

    def __call__(self, environ, start_response):
        path = environ['PATH_INFO'][1:].split('/')
        token_str = cgi.parse_qs(environ['QUERY_STRING']).get('token')

        if path[0] != "filedownload":
            start_response('404 Not found', [])
            return [""]
        if token_str is None:
            start_response('401 Unauthorized', [('Content-Type', 'text/html')])
            return [b"No Token provided so no cookie for you!"]
        self.token = self.dispatcher.token_store.lookup_token(token_str[0])
        if self.token is None or self.token.direction != "download":
            start_response('400 Bad Request', [('Content-Type', 'text/html')])
            return [b"You provided an invalid/timedout token!"]
        return self.start_file_transfer(environ, start_response)

    def start_file_transfer(self, environ, start_response):
        start_response('200 OK', [
            ('Access-Control-Allow-Origin', '*'),
            ('Access-Control-Allow-Credentials', 'true'),
            ('Content-Type', 'application/octet-stream'),
            ('Content-Disposition', 'attachment; filename="{}"'.format(self.token.name)),
            ('Transfer-Encoding', 'chunked')
        ])
        try:
            try:
                self.token.file.seek(0)
            except UnsupportedOperation:
                # if file object's underlying stream is a pipe
                # then seek is illegal
                pass

            while True:
                chunk = self.token.file.read(1024)
                if chunk == b'':
                    break
                # issue keepalive
                self.dispatcher.token_store.keepalive_token(self.token)
                yield chunk
        finally:
            self.dispatcher.token_store.delete_token(self.token)
            self.token.file.close()


def run(d, args):
    setproctitle('dispatcher')

    # Signal handlers
    gevent.signal(signal.SIGQUIT, d.die)
    gevent.signal(signal.SIGTERM, d.die)
    gevent.signal(signal.SIGINT, d.die)
    gevent.signal(signal.SIGHUP, d.reload_plugins)

    # WebSockets server
    kwargs = {}
    if d.use_tls:
        kwargs = {'certfile': d.certfile, 'keyfile': d.keyfile}

    ws_options = {
        'kwargs': kwargs,
        'apps': {
            '/shell': ShellConnection,
            '/file': FileConnection,
            '/filedownload': DownloadRequestHandler(d)
        }
    }

    # IPv4 WebSocket server
    s4 = Server(d, connection_class=DispatcherConnection)
    s4.start('ws://0.0.0.0:{0}/socket'.format(args.p), transport_options=ws_options)

    # IPv6 WebSocket server
    s6 = Server(d, connection_class=DispatcherConnection)
    s6.start('ws://[::]:{0}/socket'.format(args.p), transport_options=ws_options)

    # Unix domain socket server
    su = Server(d, connection_class=DispatcherConnection)
    su.start('unix://{0}'.format(args.u))

    d.ws_servers = [s4, s6, su]
    d.port = args.p
    d.init()

    if args.s and d.configstore.get('system.debug.ui'):
        # Debugging frontend server
        from frontend import frontend

        frontend.dispatcher = d
        http_server4 = WSGIServer(('0.0.0.0', args.s), frontend.app, **kwargs)
        http_server6 = WSGIServer(('::', args.s), frontend.app, **kwargs)

        d.http_servers.extend([http_server4, http_server6])
        logging.info('Frontend server listening on port %d', args.s)

    for i in d.http_servers:
        gevent.spawn(i.serve_forever)

    serv_threads = [
        gevent.spawn(s4.serve_forever),
        gevent.spawn(s6.serve_forever),
        gevent.spawn(su.serve_forever)
    ]

    d.discover_plugins()
    d.load_plugins()
    d.start()
    gevent.joinall(d.threads + serv_threads)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', type=str, metavar='LOG_LEVEL', default='INFO', help="Logging level")
    parser.add_argument('--log-file', type=str, metavar='LOG_FILE', help="Log to file")
    parser.add_argument('--syslog', action='store_true', help="Log to syslog")
    parser.add_argument('--logd', action='store_true', help="Log to logd")
    parser.add_argument('-s', type=int, metavar='PORT', default=8180, help="Run debug frontend server on port")
    parser.add_argument('-p', type=int, metavar='PORT', default=5000, help="WebSockets server port")
    parser.add_argument('-u', type=str, metavar='PATH', default='/var/run/dispatcher.sock', help="Unix domain server path")
    parser.add_argument('-c', type=str, metavar='CONFIG', default=DEFAULT_CONFIGFILE, help='Configuration file path')
    parser.add_argument('--load-disabled', action='store_true', help='Load disabled plugins')
    args = parser.parse_args()

    logging.setLoggerClass(TraceLogger)
    logging.basicConfig(
        level=logging.getLevelName(args.log_level),
        format=LOGGING_FORMAT
    )

    if args.log_file:
        handler = FaultTolerantLogHandler(args.log_file)
        handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
        logging.root.removeHandler(logging.root.handlers[0])
        logging.root.addHandler(handler)

    if args.syslog:
        handler = logging.handlers.SysLogHandler('/var/run/log', facility='local3')
        handler.setLevel(logging.DEBUG)
        logging.root.removeHandler(logging.root.handlers[0])
        logging.root.addHandler(handler)

    if args.logd:
        handler = LogdLogHandler(ident='dispatcher')
        logging.root.removeHandler(logging.root.handlers[0])
        logging.root.addHandler(handler)

    # Initialization and dependency injection
    d = Dispatcher(load_disabled=args.load_disabled)
    try:
        d.read_config_file(args.c)
    except IOError as err:
        logging.fatal("Cannot read config file {0}: {1}".format(args.c, str(err)))
        sys.exit(1)
    except ValueError as err:
        logging.fatal("Cannot parse config file {0}: {1}".format(args.c, str(err)))
        sys.exit(1)

    run(d, args)


if __name__ == '__main__':
    main()
