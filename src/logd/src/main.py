#
# Copyright 2017 iXsystems, Inc.
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

import uuid
import os
import sys
import re
import socket
import threading
import collections
import signal
import logging
import itertools
import time
import errno
import datastore
import datastore.config
from datetime import datetime
from bsd import setproctitle
from bsd import kinfo_getproc
from bsd import SyslogPriority, SyslogFacility
from freenas.dispatcher.server import Server
from freenas.dispatcher.rpc import RpcContext, RpcService, RpcException, generator, get_sender
from freenas.serviced import ServicedException, checkin, get_job_by_pid
from freenas.utils import query as q
from freenas.utils.debug import DebugService


FLUSH_INTERVAL = 180
RCVBUF_MINSIZE = 80 * 1024  # same as in syslogd
SYSLOG_PATTERN = re.compile(r'<(?P<priority>\d+)>(?P<syslog_timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<identifier>[\w\[\]]+): (?P<message>.*)')
KLOG_PATTERN = re.compile(r'<(?P<priority>\d+)>(?P<message>.*)')
PROC_PATTERN = re.compile(r'(?P<identifier>\w+)\[(?P<pid>\d+)\]')
DEFAULT_SOCKET_ADDRESS = 'unix:///var/run/logd.sock'
KLOG_PATH = '/dev/klog'
SYSLOG_SOCKETS = {
    '/var/run/log': 0o666,
    '/var/run/logpriv': 0o600
}


def parse_priority(prio):
    if isinstance(prio, str):
        return getattr(SyslogPriority, prio, SyslogPriority.INFO), None

    if isinstance(prio, int):
        try:
            facility = SyslogFacility(int(prio & 0x03f8) >> 3)
        except ValueError:
            facility = SyslogFacility.LOCAL

        return SyslogPriority(int(prio) & 0x7), facility


class LoggingService(RpcService):
    def __init__(self, context):
        self.context = context

    def get_boot_id(self):
        return self.context.boot_id

    def set_flush(self, enable):
        with self.context.cv:
            self.context.flush = bool(enable)
            self.context.cv.notify_all()

    def push(self, entry):
        creds = get_sender().credentials
        if creds:
            entry['pid'] = creds['pid']
            entry['uid'] = creds['uid']
            entry['gid'] = creds['gid']

        if 'identifier' not in entry:
            try:
                proc = kinfo_getproc(entry['pid'])
                entry['identifier'] = proc.command
            except OSError:
                entry['identifier'] = 'unknown'

        entry['source'] = 'rpc'
        self.context.push(entry)

    @generator
    def query_boots(self, filter=None, params=None):
        if not self.context.datastore:
            raise RpcException(errno.ENXIO, 'Datastore not initialized yet')

        return self.context.datastore.query_stream('boots', *(filter or []), **(params or {}))

    @generator
    def query(self, filter=None, params=None):
        ds_results = self.context.datastore.query_stream('syslog', *(filter or []), **(params or {})) \
            if self.context.datastore \
            else []

        return q.query(
            itertools.chain(ds_results, self.context.store),
            *(filter or []),
            stream=True,
            **(params or {})
        )


class KernelLogReader(object):
    def __init__(self, context):
        self.context = context

    def process(self):
        while True:
            with open(KLOG_PATH, 'rb') as fp:
                for line in fp:
                    # Skip lines with 'ESC' character inside
                    if b'\033' in line:
                        continue

                    line = line.decode('utf-8', 'ignore')
                    m = KLOG_PATTERN.match(line)
                    if not m:
                        m = {
                            'priority': 'INFO',
                            'message': line.strip()
                        }
                    else:
                        m = m.groupdict()

                    self.context.push({
                        'priority': m['priority'],
                        'message': m['message'],
                        'identifier': 'kernel',
                        'source': 'klog',
                        'timestamp': datetime.utcnow()
                    })

            logging.warning('Lost connection to {0}, retrying in 1 second'.format(KLOG_PATH))
            time.sleep(1)


class SyslogServer(object):
    def __init__(self, path, perms, context):
        super(SyslogServer, self).__init__()
        self.context = context
        self.path = path
        self.perms = perms
        self.thread = None
        self.sock = None

        if os.path.exists(path):
            os.unlink(path)

    def start(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        self.sock.bind(self.path)
        os.chmod(self.path, self.perms)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_MINSIZE)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def parse_message(self, msg):
        now = datetime.now()
        m = SYSLOG_PATTERN.match(msg.decode('utf-8', 'replace'))
        if not m:
            return

        m = m.groupdict()
        m.update({
            'priority': int(m['priority']),
            'syslog_timestamp': datetime.strptime(m['syslog_timestamp'], '%b %d %H:%M:%S').replace(year=now.year),
            'source': 'syslog'
        })

        p = PROC_PATTERN.match(m['identifier'])
        if not p:
            return m

        p = p.groupdict()
        m['identifier'] = p['identifier']
        m['pid'] = int(p['pid'])
        return m

    def serve(self):
        while True:
            msg, ancdata, flags, address = self.sock.recvmsg(1024)
            if not msg:
                break

            item = self.parse_message(msg)
            self.context.push(item)


class SyslogForwarder(object):
    def __init__(self, host, port, context):
        self.host = host
        self.port = port
        self.context = context
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    def close(self):
        self.sock.close()

    def forward(self, msg):
        try:
            self.sock.sendto(msg, (self.host, self.port))
        except:
            pass


class Context(object):
    def __init__(self):
        self.store = collections.deque()
        self.lock = threading.Lock()
        self.seqno = 0
        self.rpc_server = Server(self)
        self.boot_id = str(uuid.uuid4())
        self.exiting = False
        self.server = None
        self.servers = []
        self.forwarders = []
        self.klog_reader = None
        self.flush = False
        self.flush_thread = None
        self.datastore = None
        self.configstore = None
        self.started_at = datetime.utcnow()
        self.rpc = RpcContext()
        self.rpc.register_service_instance('logd.logging', LoggingService(self))
        self.rpc.register_service_instance('logd.debug', DebugService())
        self.cv = threading.Condition()

    def init_configstore(self):
        ds = datastore.get_datastore()
        self.configstore = datastore.config.ConfigStore(ds)

    def init_datastore(self):
        try:
            self.datastore = datastore.get_datastore(log=True)
            self.datastore.insert('boots', {
                'id': self.boot_id,
                'booted_at': self.started_at,
                'hostname': socket.gethostname()
            })
        except datastore.DatastoreException as err:
            logging.error('Cannot initialize datastore: %s', str(err))
            sys.exit(1)

    def init_rpc_server(self):
        self.server = Server(self)
        self.server.rpc = self.rpc
        self.rpc.streaming_enabled = True
        self.rpc.streaming_burst = 16
        self.server.streaming = True
        self.server.start(DEFAULT_SOCKET_ADDRESS, transport_options={'permissions': 0o666})
        thread = threading.Thread(target=self.server.serve_forever, name='RPC server thread', daemon=True)
        thread.start()

    def init_syslog_server(self):
        for path, perm in SYSLOG_SOCKETS.items():
            server = SyslogServer(path, perm, self)
            server.start()
            self.servers.append(server)

    def init_klog(self):
        self.klog_reader = KernelLogReader(self)
        thread = threading.Thread(target=self.klog_reader.process, name='klog reader', daemon=True)
        thread.start()

    def init_flush(self):
        self.flush_thread = threading.Thread(target=self.do_flush, name='Flush thread')
        self.flush_thread.start()

    def load_configuration(self):
        syslog_server = self.configstore.get('system.syslog_server')

        if not syslog_server:
            if self.forwarders:
                for i in self.forwarders:
                    i.close()

                self.forwarders.clear()

            return

        if ':' in syslog_server:
            host, port = syslog_server.split(':')
            port = int(port)
        else:
            host = syslog_server
            port = 514

        self.forwarders.append(SyslogForwarder(host, port, self))

    def push(self, item):
        if not item:
            return

        if 'message' not in item or 'priority' not in item:
            return

        if 'timestamp' not in item:
            item['timestamp'] = datetime.now()

        if 'pid' in item:
            try:
                job = get_job_by_pid(item['pid'], True)
                item['service'] = job['Label']
            except ServicedException:
                pass

        with self.lock:
            priority, facility = parse_priority(item['priority'])
            item.update({
                'id': str(uuid.uuid4()),
                'seqno': self.seqno,
                'boot_id': self.boot_id,
                'priority': priority.name,
                'facility': facility.name if facility else None
            })
            self.store.append(item)
            self.seqno += 1

        self.server.broadcast_event('logd.logging.message', item)
        self.forward(item)

    def forward(self, item):
        hostname = socket.gethostname()
        prio = SyslogPriority.INFO

        try:
            prio = int(getattr(SyslogPriority, item['priority']))
        except:
            pass

        msg = f'<{prio}>{item["timestamp"]:%b %d %H:%M:%S} {hostname} {item["identifier"]}: {item["message"]}'
        for i in self.forwarders:
            i.forward(msg.encode('utf-8', 'ignore'))

    def do_flush(self):
        logging.debug('Flush thread initialized')
        while True:
            # Flush immediately after getting wakeup or when timeout expires
            with self.cv:
                self.cv.wait(FLUSH_INTERVAL)

                if not self.flush:
                    continue

                if not self.datastore:
                    try:
                        self.init_datastore()
                        logging.info('Datastore initialized')
                    except BaseException as err:
                        logging.warning('Cannot initialize datastore: {0}'.format(err))
                        logging.warning('Flush skipped')
                        continue

                logging.debug('Attempting to flush logs')
                with self.lock:
                    for i in self.store:
                        self.datastore.insert('syslog', i)

                    self.store.clear()

                if self.exiting:
                    return

    def sigusr1(self, signo, frame):
        with self.cv:
            logging.info('Flushing logs on signal')
            self.flush = True
            self.cv.notify_all()

    def main(self):
        setproctitle('logd')
        self.init_configstore()
        self.init_syslog_server()
        self.init_klog()
        self.init_rpc_server()
        self.init_flush()
        self.load_configuration()
        checkin()
        signal.signal(signal.SIGUSR1, signal.SIG_DFL)
        signal.signal(signal.SIGHUP, signal.SIG_DFL)

        while True:
            sig = signal.sigwait([signal.SIGTERM, signal.SIGUSR1, signal.SIGHUP])
            if sig == signal.SIGUSR1:
                with self.cv:
                    logging.info('Flushing logs on signal')
                    self.flush = True
                    self.cv.notify_all()

                continue

            if sig == signal.SIGHUP:
                logging.info('Reloading configuration on SIGHUP')
                self.load_configuration()
                continue

            if sig == signal.SIGTERM:
                logging.info('Got SIGTERM, exiting')
                with self.cv:
                    self.exiting = True
                    self.cv.notify_all()

                self.flush_thread.join()
                break


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    c = Context()
    c.main()
