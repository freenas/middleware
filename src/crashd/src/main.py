#!/usr/local/bin/python3
#+
# Copyright 2015 iXsystems, Inc.
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
import sys
import json
import enum
import logging
import datetime
import requests
import time
import subprocess
import shutil
from bsd import setproctitle, sysctl
from threading import RLock
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from freenas.utils import configure_logging


sys.path.append('/usr/local/lib')
from freenasOS import Configuration


LOGGING_FORMAT = '%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s'
REPORTS_PATH = '/var/tmp/crash'
TELEMETRY_STAGING_PATH = '/var/tmp/telemetry'
TELEMETRY_PLUGINS_PATH = '/usr/local/libexec/telemetry'
USER_CORES_PATH = '/var/db/system/cores'
KERNEL_CORES_PATH = '/data/crash'
TELEMETRY_ENDPOINT_PATH = 'http://ext-data10.ixsystems.com/telemetry/upload'
API_ENDPOINT_PATH = 'https://api.rollbar.com/api/1/item/'
ACCESS_TOKEN = 'f65476dd78a74cde8ce5899aa3f4b58c'
RETRY_INTERVAL = 1800
logger = logging.getLogger('crashd')


class ReportType(enum.IntEnum):
    EXCEPTION = 1
    ERROR = 2


class Handler(FileSystemEventHandler):
    def __init__(self, context):
        self.context = context

    def on_created(self, event):
        with self.context.lock:
            self.context.send_report(event.src_path)


class Main(object):
    def __init__(self):
        self.observer = None
        self.last_send = datetime.datetime.now()
        self.lock = RLock()
        self.hostuuid = sysctl.sysctlbyname('kern.hostuuid')[:-1]

    def collect_telemetry(self):
        logger.info('Collecting telemetry data into {0}'.format(TELEMETRY_STAGING_PATH))
        shutil.rmtree(TELEMETRY_STAGING_PATH, ignore_errors=True)
        os.makedirs(TELEMETRY_STAGING_PATH)
        os.chdir(TELEMETRY_STAGING_PATH)

        for i in os.listdir(TELEMETRY_PLUGINS_PATH):
            logger.debug('Running telemetry plugin {0}'.format(i))
            try:
                proc = subprocess.run(
                    [os.path.join(TELEMETRY_PLUGINS_PATH, i)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    encoding='utf-8',
                    timeout=60
                )

                if proc.returncode != 0:
                    logger.warning('Telemetry plugin {0} failed, skipping'.format(i))
                    logger.warning('Failed plugin output: {0}'.format(proc.stdout))
                    continue
            except subprocess.TimeoutExpired:
                logger.warning('Timeout exceeded for telemetry plugin {0}, skipping'.format(i))
                continue
            except OSError as err:
                logger.warning('Failed to start telemetry plugin {0}: {1}'.format(i, err))
                continue

        logger.info('Telemetry collection finished')

    def send_telemetry(self):
        logger.info('Uploading telemetry data to {0}'.format(TELEMETRY_ENDPOINT_PATH))
        conf = Configuration.Configuration()
        conf.LoadTrainsConfig()
        manifest = conf.SystemManifest()
        headers = {
            'X-iXSystems-Project': Configuration.Avatar(),
            'X-iXSystems-Version': manifest.Version(),
            'X-iXSystems-HostID': self.hostuuid,
            'X-iXSystems-Train': conf.CurrentTrain()
        }

        manifest = {
            'host_uuid': self.hostuuid,
            'cpu_type': sysctl.sysctlbyname("hw.model"),
            'cpu_clock': sysctl.sysctlbyname("hw.clockrate"),
            'cpu_cores': sysctl.sysctlbyname("hw.ncpu"),
            'hypervisor': sysctl.sysctlbyname("kern.vm_guest"),
            'mem_size': sysctl.sysctlbyname("hw.physmem")
        }

        files = {
            name: open(os.path.join(TELEMETRY_STAGING_PATH, name), 'rb')
            for name in os.listdir(TELEMETRY_STAGING_PATH)
        }

        files['manifest'] = (None, json.dumps(manifest), 'application/json')

        try:
            requests.post(TELEMETRY_ENDPOINT_PATH, headers=headers, files=files)
        except BaseException as err:
            logger.error('Cannot send telemerty data: {0}'.format(str(err)))

        # Remove the collected files
        shutil.rmtree(TELEMETRY_STAGING_PATH, ignore_errors=True)
        self.last_send = datetime.datetime.now()

    def send_report(self, path):
        name, ext = os.path.splitext(os.path.basename(path))
        body = None

        try:
            with open(path) as f:
                data = f.read()
        except:
            return

        if ext == '.json':
            try:
                jdata = json.loads(data)
                jdata['type'] = getattr(ReportType, jdata['type'].upper()).name
            except ValueError:
                logger.warning('Cannot decode JSON from {0}'.format(path))
                #os.unlink(path)
                return

        elif ext == '.log':
            jdata = {
                'timestamp': datetime.datetime.now(),
                'type': ReportType.ERROR.name
            }

        else:
            logger.warning('Unknown file type: {0}, removing {1}'.format(ext, path))
            os.unlink(path)
            return

        jdata['uuid'] = self.hostuuid
        jdata['format'] = 'json'

        logger.info('Sending report {0}...'.format(path))
        logger.debug('jdata: {0}'.format(json.dumps(jdata)))

        if jdata['type'] == ReportType.EXCEPTION.name:
            body = {'trace': jdata['exception']}

        if jdata['type'] == ReportType.ERROR.name:
            body = {
                'message': {
                    'body': jdata['message'],
                    'exit_code': jdata['exit_code'],
                    'application': jdata['application']
                }
            }

        report = {
            'access_token': ACCESS_TOKEN,
            'level': 'error',
            'request': {
                'user_ip': '$remote_ip'
            },
            'title': jdata.get('title'),
            'data': {
                'environment': 'production',
                'body': body
            }
        }

        try:
            response = requests.post(API_ENDPOINT_PATH, json=report, headers={'Content-Type': 'application/json'})
            if response.status_code != 200:
                logger.warning('Cannot send report {0}: Server error code: {1}'.format(path, response.status_code))
                return
        except BaseException as err:
            logger.warning('Cannot send report {0}: {1}'.format(path, str(err)))
            return

        os.unlink(path)

    def main(self):
        setproctitle('crashd')
        configure_logging('crashd', 'DEBUG')
        logger.info('Started')

        if not os.path.isdir(REPORTS_PATH):
            os.mkdir(REPORTS_PATH)

        self.observer = Observer()
        self.observer.schedule(Handler(self), path=REPORTS_PATH, recursive=False)
        self.observer.start()

        while True:
            if not self.last_send or self.last_send + datetime.timedelta(hours=24) < datetime.datetime.now():
                self.collect_telemetry()
                self.send_telemetry()

            for i in os.listdir(REPORTS_PATH):
                with self.lock:
                    self.send_report(os.path.join(REPORTS_PATH, i))

            time.sleep(RETRY_INTERVAL)


if __name__ == '__main__':
    m = Main()
    m.main()
