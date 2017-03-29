#
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

import gevent.monkey
gevent.monkey.patch_all()

import os
import enum
import sys
import re
import argparse
import json
import logging
import errno
import time
import string
import random
import gevent
import gevent.os
import subprocess
import serial
import netif
import socket
import signal
import select
import tempfile
import docker
import dockerpty
import ipaddress
import pf
import urllib.parse
import requests
import contextlib
import collections
import dhcp.client as dhcp
from docker.errors import NotFound, APIError
from datetime import datetime
from bsd import kld, sysctl, setproctitle
from threading import Condition
from gevent.queue import Queue
from gevent.event import Event
from gevent.lock import RLock
from gevent.threadpool import ThreadPool
from geventwebsocket import WebSocketServer, WebSocketApplication, Resource
from geventwebsocket.exceptions import WebSocketError
from pyee import EventEmitter
from datastore import DatastoreException, get_datastore
from datastore.config import ConfigStore
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.rpc import RpcService, RpcException, private, generator
from freenas.dispatcher.jsonenc import loads
from freenas.utils.debug import DebugService
from freenas.utils import bool_to_truefalse, truefalse_to_bool, normalize, first_or_default, configure_logging, query as q
from freenas.serviced import checkin
from vnc import app
from mgmt import ManagementNetwork
from proxy import ReverseProxyServer


BOOTROM_PATH = '/usr/local/share/uefi-firmware/BHYVE_UEFI.fd'
BOOTROM_CSM_PATH = '/usr/local/share/uefi-firmware/BHYVE_UEFI_CSM.fd'
MGMT_INTERFACE = 'mgmt0'
NAT_INTERFACE = 'nat0'
DEFAULT_CONFIGFILE = '/usr/local/etc/middleware.conf'
SCROLLBACK_SIZE = 20 * 1024

vtx_enabled = False
svm_features = False
unrestricted_guest = True
threadpool = ThreadPool(128)

logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib').setLevel(logging.WARNING)

DOCKER_LABELS_MAP = {
    'org.freenas.autostart': {'default': 'false', 'preset': 'autostart'},
    'org.freenas.capabilities-add': {'default': '', 'preset': 'capabilities_add'},
    'org.freenas.capabilities-drop': {'default': '', 'preset': 'capabilities_drop'},
    'org.freenas.command': {'default': '', 'preset': 'command'},
    'org.freenas.dhcp': {'default': 'false', 'preset': 'bridge.dhcp'},
    'org.freenas.expose-ports-at-host': {'default': 'false', 'preset': 'expose_ports'},
    'org.freenas.immutable': {'default': '', 'preset': 'immutable'},
    'org.freenas.interactive': {'default': 'false', 'preset': 'interactive'},
    'org.freenas.port-mappings': {'default': '', 'preset': 'ports'},
    'org.freenas.primary-network-mode': {'default': None, 'preset': 'primary_network_mode'},
    'org.freenas.privileged': {'default': 'false', 'preset': 'privileged'},
    'org.freenas.settings': {'default': [], 'preset': 'settings'},
    'org.freenas.static-volumes': {'default': [], 'preset': 'static_volumes'},
    'org.freenas.upgradeable': {'default': 'false', 'preset': 'upgradeable'},
    'org.freenas.version': {'default': '0', 'preset': 'version'},
    'org.freenas.volumes': {'default': [], 'preset': 'volumes'},
    'org.freenas.web-ui-path': {'default': '', 'preset': 'web_ui_path'},
    'org.freenas.web-ui-port': {'default': '', 'preset': 'web_ui_port'},
    'org.freenas.web-ui-protocol': {'default': '', 'preset': 'web_ui_protocol'},
}


def normalize_docker_labels(labels):
    normalize(labels, {e: v.get('default') for e, v in DOCKER_LABELS_MAP.items()})
    return labels


class VirtualMachineState(enum.Enum):
    STOPPED = 1
    BOOTLOADER = 2
    RUNNING = 3
    PAUSED = 4
    STOPPING = 5


class DockerHostState(enum.Enum):
    DOWN = 1
    OFFLINE = 2
    UP = 3


class ConsoleToken(object):
    def __init__(self, type, id):
        self.type = type
        self.id = id


def generate_id():
    return ''.join([random.choice(string.ascii_letters + string.digits) for _ in range(32)])


def get_docker_ports(details):
    if 'HostConfig' not in details:
        return

    if 'PortBindings' not in details['HostConfig']:
        return

    if not details['HostConfig']['PortBindings']:
        return

    for port, config in details['HostConfig']['PortBindings'].items():
        num, proto = port.split('/')
        yield {
            'protocol': proto.upper(),
            'container_port': int(num),
            'host_port': int(config[0]['HostPort'])
        }


def get_docker_volumes(details):
    if 'Mounts' not in details:
        return

    for mnt in details['Mounts']:
        yield {
            'host_path': mnt['Source'],
            'container_path': mnt['Destination'],
            'readonly': not mnt['RW'],
            'source': 'HOST' if mnt['Source'].startswith('/host') else 'VM'
        }


def get_interactive(details):
    config = details.get('Config')
    if not config:
        return False

    return config.get('Tty') and config.get('OpenStdin')



def unpack_docker_error(err):
    try:
        return json.loads(err.explanation).get('message', '')
    except:
        return str(err)


class BinaryRingBuffer(object):
    def __init__(self, size):
        self.data = bytearray(size)

    def push(self, data):
        del self.data[0:len(data)]
        self.data += data

    def read(self):
        return self.data


class VirtualMachine(object):
    def __init__(self, context, name):
        self.context = context
        self.id = None
        self.name = name
        self.nmdm = None
        self.state = VirtualMachineState.STOPPED
        self.guest_type = 'other'
        self.health = 'UNKNOWN'
        self.config = None
        self.devices = []
        self.bhyve_process = None
        self.output_thread = None
        self.scrollback = BinaryRingBuffer(SCROLLBACK_SIZE)
        self.console_fd = None
        self.console_queues = []
        self.console_thread = None
        self.tap_interfaces = {}
        self.vnc_socket = None
        self.vnc_port = None
        self.active_vnc_ports = []
        self.vmtools_client = None
        self.vmtools_ready = False
        self.vmtools_thread = None
        self.thread = None
        self.exiting = False
        self.docker_host = None
        self.interfaces_mappings = []
        self.network_ready = Event()
        self.logger = logging.getLogger('VM:{0}'.format(self.name))
        self.run_lock = RLock()
        self.autostart = False
        self.dropped_devices = []

    @property
    def management_lease(self):
        return self.context.mgmt.allocations.get(self.get_link_address('MANAGEMENT'))

    @property
    def nat_lease(self):
        return self.context.mgmt.allocations.get(self.get_link_address('NAT'))

    @property
    def vmtools_socket(self):
        return '/var/run/containerd/{0}.vmtools.sock'.format(self.id)

    @property
    def vm_root(self):
        return self.context.client.call_sync('vm.get_vm_root', self.id)

    @property
    def files_root(self):
        return os.path.join(self.vm_root, 'files')

    def get_link_address(self, mode):
        nic = first_or_default(
            lambda d: d['type'] == 'NIC' and d['properties']['mode'] == mode,
            self.devices
        )

        if not nic:
            return None

        return nic['properties']['link_address']

    def build_args(self):
        xhci_devices = {}
        args = [
            '/usr/sbin/bhyve', '-A', '-H', '-P', '-c', str(self.config['ncpus']), '-m', str(self.config['memsize'])]

        if self.config['bootloader'] in ['UEFI', 'UEFI_CSM']:
            index = 3
        else:
            index = 1
            args += ['-s', '0:0,hostbridge']

        for i in self.devices:
            if i['type'] == 'DISK':
                drivermap = {
                    'AHCI': 'ahci-hd',
                    'VIRTIO': 'virtio-blk'
                }

                driver = drivermap.get(i['properties'].get('mode', 'AHCI'))
                path = self.context.client.call_sync('vm.get_device_path', self.id, i['name'])
                args += ['-s', '{0}:0,{1},{2}'.format(index, driver, path)]
                index += 1

            if i['type'] == 'CDROM':
                path = self.context.client.call_sync('vm.get_device_path', self.id, i['name'])
                args += ['-s', '{0}:0,ahci-cd,{1}'.format(index, path)]
                index += 1

            if i['type'] == 'VOLUME':
                if i['properties']['type'] == 'VT9P':
                    path = self.context.client.call_sync('vm.get_device_path', self.id, i['name'])
                    args += ['-s', '{0}:0,virtio-9p,{1}={2}'.format(index, i['name'], path)]
                    index += 1

            if i['type'] == 'NIC':
                drivermap = {
                    'VIRTIO': 'virtio-net',
                    'E1000': 'e1000',
                    'NE2K': 'ne2k'
                }

                mac = i['properties']['link_address']
                iface = self.init_tap(i['name'], i['properties'], mac)
                if not iface:
                    continue

                driver = drivermap.get(i['properties'].get('device', 'VIRTIO'))
                args += ['-s', '{0}:0,{1},{2},mac={3}'.format(index, driver, iface, mac)]
                index += 1

            if i['type'] == 'GRAPHICS':
                if i['properties'].get('vnc_enabled', False):
                    port = i['properties'].get('vnc_port', 5900)
                    self.init_vnc(index, vnc_enabled=True, vnc_port=port)
                else:
                    self.init_vnc(index, vnc_enabled=False)

                w, h = i['properties']['resolution'].split('x')
                vga = self.guest_type not in ('openbsd32', 'openbsd64')
                args += ['-s', '{0}:0,fbuf,unix={1},w={2},h={3},vncserver,vga={4}'.format(
                    index, self.vnc_socket, w, h,
                    'io' if vga else 'off'
                )]

                index += 1

            if i['type'] == 'USB':
                xhci_devices[i['properties']['device']] = i.get('config')

            if i['type'] == 'SCSI':
                properties = i['properties']
                args += ['-s', '{0}:0,virtio-scsi,dev=/dev/cam/ctl{1}.0,iid={2}'.format(
                    index,
                    properties['port'],
                    properties['initiator_id'] or 7
                )]
                index += 1

        if xhci_devices:
            args += ['-s', '{0}:0,xhci,{1}'.format(index, ','.join(xhci_devices.keys()))]
            index += 1

        args += ['-s', '30,virtio-console,org.freenas.vm-tools={0}'.format(self.vmtools_socket)]
        args += ['-s', '31,lpc', '-l', 'com1,{0}'.format(self.nmdm[0])]

        if self.config['bootloader'] == 'UEFI':
            args += ['-l', 'bootrom,{0}'.format(BOOTROM_PATH)]

        if self.config['bootloader'] == 'UEFI_CSM':
            args += ['-l', 'bootrom,{0}'.format(BOOTROM_CSM_PATH)]

        if self.guest_type == 'freebsd64':
            args += ['-W']

        args.append(self.name)
        self.logger.debug('bhyve args: {0}'.format(args))
        return args

    def build_env(self):
        ret = {}

        if 'LIB9P' in self.config['logging']:
            ret['LIB9P_LOGGING'] = os.path.join(self.vm_root, 'lib9p.log')

        return ret

    def init_vnc(self, index, vnc_enabled, vnc_port=5900):
        self.vnc_socket = '/var/run/containerd/{0}.{1}.vnc.sock'.format(self.id, index)
        self.cleanup_vnc(vnc_port)

        if vnc_enabled:
            self.context.proxy_server.add_proxy(vnc_port, self.vnc_socket)
            self.active_vnc_ports.append(vnc_port)

    def vmtools_worker(self):
        def vmtools_ready(args):
            self.logger.info('freenas-vm-tools on VM {0} initialized'.format(self.name))
            self.vmtools_ready = True
            self.changed()

        def vmtools_state_changed():
            self.context.client.emit_event('vmtools.state.changed', {'state': self.health, 'id': self.id})

        try:
            self.vmtools_client = Client()
            self.vmtools_client.connect('unix://{0}'.format(self.vmtools_socket))
            self.vmtools_client.register_event_handler('vmtools.ready', vmtools_ready)
        except Exception as err:
            self.logger.warning(f'Failed to initialize vm-tools connection for VM {self.name} <{self.id}>: {err}')
            return

        while True:
            time.sleep(60)
            if not self.vmtools_ready:
                continue

            try:
                self.vmtools_client.call_sync('system.ping')
                if self.health in ('HEALTHY', 'UNKNOWN'):
                    self.health = 'HEALTHY'
                    self.changed()
                    vmtools_state_changed()
            except RpcException as err:
                self.logger.warning('Ping VM {0} failed: {1}'.format(self.name, str(err)))
                if self.health == 'HEALTHY':
                    self.health = 'DYING'
                    self.changed()
                    vmtools_state_changed()
                    continue

                if self.health == 'DYING':
                    self.health = 'DEAD'
                    self.changed()
                    vmtools_state_changed()
                    continue

    def call_vmtools(self, method, *args, timeout=None):
        if not self.vmtools_ready:
            raise RpcException(errno.ENXIO, 'freenas-vm-tools service not ready or not present')

        return self.vmtools_client.call_sync(method, *args, timeout=timeout)

    def cleanup_vnc(self, vnc_port=None):
        if vnc_port:
            self.context.proxy_server.remove_proxy(vnc_port)
        else:
            for p in self.active_vnc_ports:
                self.context.proxy_server.remove_proxy(p)

        if self.vnc_socket and os.path.exists(self.vnc_socket):
            os.unlink(self.vnc_socket)

    def init_tap(self, name, nic, mac):
        iface_mapping = {}
        try:
            iface = netif.get_interface(netif.create_interface('tap'))
            iface.description = 'vm:{0}:{1}'.format(self.name, name)
            iface.up()
            iface_mapping['tap'] = iface.name
            iface_mapping['mode'] = nic['mode']

            if nic['mode'] == 'BRIDGED':
                if nic.get('bridge'):
                    self.logger.debug('Creating a bridged interface for {0}'.format(name))
                    bridge_if = nic['bridge']
                    if bridge_if == 'default':
                        try:
                            bridge_if = self.context.client.call_sync(
                                'networkd.configuration.wait_for_default_interface',
                                600,
                                timeout=600
                            )
                        except RpcException:
                            self.logger.warning(f'Cannot initialize NIC {name}: Cannot resolve default interface')
                            return

                        if not bridge_if:
                            self.logger.error('Error creating {0}. Default interface does not exist'.format(name))

                        self.logger.debug('{0} is bridged to a default interface {1}'.format(name, bridge_if))

                    self.logger.debug('Creating a bridged interface')

                    if_by_description = self.context.client.call_sync(
                        'network.interface.query',
                        [('name', '=', bridge_if)],
                        {'single': True, 'select': 'id'}
                    )
                    if if_by_description:
                        bridge_if = if_by_description
                        self.logger.debug(
                            'Found an interface for {0} nic by its description: {1}'.format(name, bridge_if)
                        )

                    try:
                        target_if = netif.get_interface(bridge_if)
                    except KeyError:
                        raise RpcException(errno.ENOENT, 'Target interface {0} does not exist'.format(bridge_if))

                    if isinstance(target_if, netif.BridgeInterface):
                        iface_mapping['target'] = first_or_default(lambda i: 'tap' not in i, target_if.members)
                        target_if.add_member(iface.name)
                        self.logger.debug('{0} is a bridge. Adding {1}'.format(bridge_if, name))
                    else:
                        iface_mapping['target'] = target_if.name
                        bridges = list(b for b in netif.list_interfaces().keys())
                        for b in bridges:
                            if not b.startswith(('brg', 'bridge')):
                                continue

                            bridge = netif.get_interface(b, bridge=True)
                            if bridge_if in bridge.members:
                                bridge.add_member(iface.name)
                                self.logger.debug(
                                    '{0} is already in a bridge {1}. Adding {2}'.format(bridge_if, bridge.name, name)
                                )
                                break
                        else:
                            new_bridge = netif.get_interface(netif.create_interface('bridge'))
                            new_bridge.description = 'vm bridge to {0}'.format(bridge_if)
                            new_bridge.up()
                            new_bridge.add_member(bridge_if)
                            new_bridge.add_member(iface.name)
                            new_bridge.rename('brg{0}'.format(len(bridges)))
                            self.logger.debug(
                                'Created a new bridge brg{0}. Added {1} and {2}'.format(len(bridges), name, bridge_if)
                            )

            if nic['mode'] == 'MANAGEMENT':
                iface_mapping['target'] = 'mgmt0'
                mgmt = netif.get_interface('mgmt0', bridge=True)
                mgmt.add_member(iface.name)

            if nic['mode'] == 'NAT':
                iface_mapping['target'] = 'nat0'
                mgmt = netif.get_interface('nat0', bridge=True)
                mgmt.add_member(iface.name)

            self.interfaces_mappings.append(iface_mapping)
            self.tap_interfaces[iface] = mac
            return iface.name
        except (KeyError, OSError) as err:
            self.logger.warning('Cannot initialize NIC {0}: {1}'.format(name, str(err)))
            return

    def cleanup_tap(self, iface):
        bridges = list(b for b in netif.list_interfaces().keys() if 'brg' in b)
        for b in bridges:
            bridge = netif.get_interface(b, bridge=True)
            if iface.name in bridge.members:
                bridge.delete_member(iface.name)

            if len([b for b in bridge.members]) == 1:
                bridge.down()
                netif.destroy_interface(bridge.name)

        iface.down()
        netif.destroy_interface(iface.name)

    def get_nmdm(self):
        index = self.context.allocate_nmdm()
        return '/dev/nmdm{0}A'.format(index), '/dev/nmdm{0}B'.format(index)

    def start(self):
        self.context.init_mgmt()
        self.context.logger.info('Starting VM {0} ({1})'.format(self.name, self.id))
        self.nmdm = self.get_nmdm()
        dropped_devices = list(self.drop_invalid_devices())
        self.thread = gevent.spawn(self.run)
        self.console_thread = gevent.spawn(self.console_worker)
        return dropped_devices

    def get_invalid_storage(self):
        for i in self.devices:
            if i['type'] in ('DISK', 'VOLUME'):
                path = self.context.client.call_sync('vm.get_device_path', self.id, i['name'])
                if not path or not os.path.exists(path):
                    yield i['name']

    def drop_invalid_devices(self):
        for i in list(self.devices):
            if i['type'] in ('DISK', 'CDROM', 'VOLUME'):
                path = self.context.client.call_sync('vm.get_device_path', self.id, i['name'])
                if not path or not os.path.exists(path):
                    self.dropped_devices.append(i['name'])
                    self.devices.remove(i)
                    yield i
            if i['type'] == 'NIC' and q.get(i, 'properties.mode') == 'BRIDGED':
                iface_name = q.get(i, 'properties.bridge')
                iface_id = self.context.default_if if iface_name == 'default' else iface_name
                mtu = self.context.client.call_sync(
                    'network.interface.query',
                    [('id', '=', iface_id)],
                    {'select': 'mtu', 'single': True}
                )
                # bhyve limitation
                if mtu and mtu > 1500:
                    self.dropped_devices.append(i['name'])
                    self.devices.remove(i)
                    yield i

    def stop(self, force=False):
        self.logger.info('Stopping VM {0}'.format(self.name))

        with self.run_lock:
            self.set_state(VirtualMachineState.STOPPING)
            if self.bhyve_process:
                try:
                    if force:
                        self.bhyve_process.kill()
                    else:
                        self.bhyve_process.terminate()
                except ProcessLookupError:
                    self.logger.warning('bhyve process is already dead')

        try:
            self.thread.get(timeout=60)
        except gevent.Timeout:
            raise RpcException(errno.ETIMEDOUT, f'Timeout while waiting for VM to stop')
        except BaseException as err:
            raise RpcException(errno.EFAULT, f'Cannot stop VM: {err}')

        # Clear console
        gevent.kill(self.console_thread)
        for i in self.console_queues:
            i.put(b'\033[2J')

    def set_state(self, state):
        self.logger.debug('State change: {0} -> {1}'.format(self.state, state))
        self.state = state
        self.changed()

    def changed(self):
        if self.management_lease and self.docker_host:
            self.network_ready.set()

        self.context.client.emit_event('vm.changed', {
            'operation': 'update',
            'ids': [self.id]
        })

    def run(self):
        while not self.exiting:
            self.logger.debug('Cancelling active alerts for VM {0}'.format(self.name))
            alert = self.context.client.call_sync(
                'alert.get_active_alert',
                'VirtualMachineDied',
                self.name
            )
            if alert:
                self.context.client.call_sync('alert.cancel', alert['id'])

            with self.run_lock:
                self.set_state(VirtualMachineState.BOOTLOADER)
                subprocess.call(['/usr/sbin/bhyvectl', '--destroy', '--vm={0}'.format(self.name)])
                self.context.vm_started.set()
                self.logger.debug('Starting bootloader...')

                if self.config['bootloader'] == 'GRUB':
                    with tempfile.NamedTemporaryFile('w+', delete=False) as devmap:
                        hdcounter = 0
                        cdcounter = 0
                        bootname = ''
                        bootswitch = '-r'

                        for i in filter(lambda i: i['type'] in ('DISK', 'CDROM'), self.devices):
                            path = self.context.client.call_sync('vm.get_device_path', self.id, i['name'])

                            if i['type'] == 'DISK':
                                name = 'hd{0}'.format(hdcounter)
                                hdcounter += 1

                            elif i['type'] == 'CDROM':
                                name = 'cd{0}'.format(cdcounter)
                                cdcounter += 1

                            print('({0}) {1}'.format(name, path), file=devmap)
                            if 'boot_device' in self.config:
                                if i['name'] == self.config['boot_device']:
                                    bootname = name

                        if self.config.get('boot_partition'):
                            bootname += ',{0}'.format(self.config['boot_partition'])

                        if self.config.get('boot_directory'):
                            bootswitch = '-d'
                            bootname = os.path.join(self.files_root, self.config['boot_directory'])

                        devmap.flush()
                        self.bhyve_process = subprocess.Popen(
                            [
                                '/usr/local/sbin/grub-bhyve', '-M', str(self.config['memsize']),
                                bootswitch, bootname, '-m', devmap.name, '-c', self.nmdm[0], self.name
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            close_fds=True
                        )

                if self.config['bootloader'] == 'BHYVELOAD':
                    path = self.context.client.call_sync('vm.get_device_path', self.id, self.config['boot_device'])
                    self.bhyve_process = subprocess.Popen(
                        [
                            '/usr/sbin/bhyveload', '-c', self.nmdm[0], '-m', str(self.config['memsize']),
                            '-d', path, self.name,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        close_fds=True
                    )

            if self.config['bootloader'] not in ('UEFI', 'UEFI_CSM'):
                out, err = self.bhyve_process.communicate()
                self.bhyve_process.wait()
                self.logger.debug('bhyveload: {0}'.format(out))

            if self.bhyve_process and self.bhyve_process.returncode != 0:
                self.set_state(VirtualMachineState.STOPPED)
                return

            with self.run_lock:
                if self.state == VirtualMachineState.STOPPING:
                    self.logger.debug('Cancelling bhyve start. Stop ordered')

                else:
                    self.logger.debug('Starting bhyve...')
                    args = self.build_args()
                    env = self.build_env()

                    self.set_state(VirtualMachineState.RUNNING)
                    self.bhyve_process = subprocess.Popen(
                        args,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        close_fds=True,
                        env=env
                    )

                    # Now it's time to start vmtools worker, because bhyve should be running now
                    self.vmtools_thread = gevent.spawn(self.vmtools_worker)
                    self.output_thread = gevent.spawn(self.output_worker)

            if self.bhyve_process:
                self.bhyve_process.wait()

            # not yet - broken in gevent
            # while True:
            #    pid, status = self.waitpid()
            #    if os.WIFSTOPPED(status):
            #        self.set_state(VirtualMachineState.PAUSED)
            #        continue
            #
            #    if os.WIFCONTINUED(status):
            #        self.set_state(VirtualMachineState.RUNNING)
            #        continue
            #
            #    if os.WIFEXITED(status):
            #        self.logger.info('bhyve process exited with code {0}'.format(os.WEXITSTATUS(status)))
            #        break

            with contextlib.suppress(OSError):
                os.unlink(self.vmtools_socket)

            subprocess.call(['/usr/sbin/bhyvectl', '--destroy', '--vm={0}'.format(self.name)])
            if self.state != VirtualMachineState.STOPPING:
                exit_code = self.bhyve_process.returncode

                if exit_code not in (0, 1, 2):
                    self.context.client.call_sync('alert.emit', {
                        'clazz': 'VirtualMachineDied',
                        'target': self.name,
                        'title': 'Virtual machine {0} exited abruptly.'.format(self.name),
                        'description': 'Virtual machine {0} has exited with status {1}'.format(
                            self.name,
                            exit_code
                        )
                    })

                if exit_code == 0 or self.autostart:
                    new_vm = self.context.client.call_sync('vm.query', [('id', '=', self.id)], {'single': True})
                    if new_vm:
                        self.logger.debug(f'Reinitializing VM {self.name} with new settings')
                        self.name = new_vm['name']
                        self.id = new_vm['id']
                        self.guest_type = new_vm['guest_type']
                        self.config = new_vm['config']
                        self.devices = new_vm['devices']
                        self.autostart = q.get(new_vm, 'config.autostart', False)
                        list(self.drop_invalid_devices())
                    continue

            break

        for i in self.tap_interfaces:
            self.cleanup_tap(i)

        self.cleanup_vnc()
        self.set_state(VirtualMachineState.STOPPED)
        if self.docker_host:
            self.logger.debug('VM {0} was a Docker host - shutting down Docker facilities'.format(self.name))
            self.docker_host.shutdown()
            self.context.docker_hosts.pop(self.id, None)

    def waitpid(self):
        return os.waitpid(self.bhyve_process.pid, os.WUNTRACED | os.WCONTINUED)

    def output_worker(self):
        for line in self.bhyve_process.stdout:
            self.logger.debug('bhyve: {0}'.format(line.decode('utf-8', 'ignore').strip()))

    def console_worker(self):
        self.logger.debug('Opening console at {0}'.format(self.nmdm[1]))
        self.console_fd = serial.Serial(self.nmdm[1], 115200)
        while True:
            try:
                fd = self.console_fd.fileno()
                r, w, x = select.select([fd], [], [])
                if fd not in r:
                    continue

                ch = self.console_fd.read(self.console_fd.inWaiting())
            except serial.SerialException as e:
                print('Cannot read from serial port: {0}'.format(str(e)))
                gevent.sleep(1)
                self.console_fd = serial.Serial(self.nmdm[1], 115200)
                continue

            self.scrollback.push(ch)
            try:
                for i in self.console_queues:
                    i.put(ch, block=False)
            except:
                pass

    def console_register(self):
        queue = gevent.queue.Queue(4096)
        self.console_queues.append(queue)
        return queue

    def console_unregister(self, queue):
        self.console_queues.remove(queue)

    def console_write(self, data):
        try:
            self.console_fd.write(data)
            self.console_fd.flush()
        except (ValueError, OSError):
            pass


class Jail(object):
    def __init__(self):
        self.id = None
        self.jid = None
        self.name = None

    def start(self):
        pass

    def stop(self):
        pass


class DockerHost(object):
    def __init__(self, context, vm):
        self.context = context
        self.vm = vm
        self.state = DockerHostState.DOWN
        self.connection = None
        self.listener = None
        self.mapped_ports = {}
        self.active_consoles = {}
        self.ready = Event()
        self.logger = logging.getLogger(self.__class__.__name__)
        gevent.spawn(self.wait_ready)

    def wait_ready(self):
        self.vm.network_ready.wait()
        ip = self.vm.management_lease.lease.client_ip
        connection = None
        ready = False

        while ready != 'OK':
            try:
                connection = docker.Client(base_url='http://{0}:2375'.format(ip), version='auto', timeout=240)
                ready = connection.ping()
            except (requests.exceptions.RequestException, docker.errors.DockerException):
                gevent.sleep(1)

        self.connection = connection
        self.logger.info('Docker instance at {0} ({1}) is ready'.format(self.vm.name, ip))
        self.listener = gevent.spawn(self.listen)

        # Initialize the bridge network
        default_if = self.context.client.call_sync('network.interface.query', [('id', '=', self.context.default_if)], {'single': True})
        alias = first_or_default(lambda a: a['type'] == 'INET', q.get(default_if, 'status.aliases'))
        network_config = self.context.client.call_sync('network.config.get_config')

        if alias and q.get(network_config, 'gateway.ipv4'):
            external = first_or_default(lambda n: n['Name'] == 'external', self.connection.networks())
            oldsubnet = q.get(external, 'IPAM.Config.0.Subnet')
            currsubnet = str(ipaddress.ip_interface('{address}/{netmask}'.format(**alias)).network)
            if external and oldsubnet != currsubnet:
                self.logger.info('Detected subnet change on {0} bridged interface. Old: {1}, New: {2}'.format(
                    self.vm.name, oldsubnet, currsubnet
                ))
                self.connection.remove_network('external')
                external = False

            if not external:
                try:
                    self.connection.create_network(
                        name='external',
                        driver='macvlan',
                        options={'parent': 'eth1'},
                        ipam=docker.utils.create_ipam_config(
                            pool_configs=[
                                docker.utils.create_ipam_pool(
                                    subnet=currsubnet,
                                    gateway=q.get(network_config, 'gateway.ipv4')
                                )
                            ]
                        )
                    )
                except BaseException as err:
                    self.logger.warning('Cannot create docker external network: {0}'.format(err))

        self.notify()
        self.init_autostart()

        docker_config = self.context.client.call_sync('docker.config.get_config')
        if self.vm.id == docker_config['api_forwarding'] and docker_config['api_forwarding_enable']:
            try:
                self.context.set_docker_api_forwarding(None)
                self.context.set_docker_api_forwarding(self.vm.id)
            except ValueError as err:
                self.logger.warning(
                    'Failed to set up Docker API forwarding to Docker host {0}: {1}'.format(self.vm.name, err)
                )

    def notify(self):
        self.ready.set()
        self.context.client.emit_event('containerd.docker.host.changed', {
            'operation': 'create',
            'ids': [self.vm.id]
        })

    def init_autostart(self):
        for container in self.connection.containers(all=True):
            details = self.connection.inspect_container(container['Id'])
            if truefalse_to_bool(q.get(details, 'Config.Labels.org\.freenas\.autostart')):
                try:
                    self.connection.start(container=container['Id'])
                except BaseException as err:
                    self.logger.warning(
                        'Failed to start {0} container automatically: {1}'.format(q.get(container, 'Names.0'), unpack_docker_error(err))
                    )

    def listen(self):
        self.logger.debug('Listening for docker events on {0}'.format(self.vm.name))
        actions = {
            'create': 'create',
            'pull': 'create',
            'destroy': 'delete',
            'delete': 'delete',
            'connect': 'update',
            'disconnect': 'update',
        }

        while True:
            events = self.connection.events(decode=True)
            self.logger.debug(f'Docker host VM {self.vm.name} starting to listen on events')
            self.context.client.call_sync('docker.host.refresh_cache', self.vm.id, timeout=600)
            self.logger.debug(f'Docker host VM {self.vm.name} local cache synced')
            try:
                for ev in events:
                    self.logger.debug('Received docker event: {0}'.format(ev))
                    if ev['Type'] == 'container':
                        self.context.client.emit_event('containerd.docker.container.changed', {
                            'operation': actions.get(ev['Action'], 'update'),
                            'ids': [ev['id']]
                        })
                        name = q.get(ev, 'Actor.Attributes.name')

                        if ev['Action'] == 'die':
                            details = self.connection.inspect_container(ev['id'])
                            state = details['State']
                            if not state.get('Running') and state.get('ExitCode') not in (None, 0, 137):
                                self.context.client.call_sync('alert.emit', {
                                    'clazz': 'DockerContainerDied',
                                    'target': name,
                                    'title': 'Docker container {0} exited with nonzero status.'.format(name),
                                    'description': 'Docker container {0} has exited with status {1}'.format(
                                        name,
                                        state.get('ExitCode')
                                    )
                                })
                                self.logger.debug('Container {0} exited with nonzero status {1}'.format(
                                    name,
                                    state.get('ExitCode')
                                ))

                        elif ev['Action'] == 'oom':
                            self.context.client.call_sync('alert.emit', {
                                'clazz': 'DockerContainerDied',
                                'target': name,
                                'title': 'Docker container {0} ran out of memory.'.format(name),
                                'description': 'Docker container {0} has run out of memory.'.format(name)
                            })
                            self.logger.debug('Container {0} has run out of memory'.format(name))

                        p = pf.PF()

                        if ev['Action'] in ('destroy', 'die'):
                            self.logger.debug(
                                'Container {0} has been stopped - cleaning port redirections'.format(name)
                            )
                            for i in self.mapped_ports.get(ev['id'], {}):
                                rule = first_or_default(lambda r: r.proxy_ports[0] == i, p.get_rules('rdr'))
                                if rule:
                                    p.delete_rule('rdr', rule.index)

                        elif ev['Action'] == 'start':
                            self.logger.debug('Cancelling active alerts for container {0}'.format(name))
                            alert = self.context.client.call_sync(
                                'alert.get_active_alert',
                                'DockerContainerDied',
                                name
                            )
                            if alert:
                                self.context.client.call_sync('alert.cancel', alert['id'])

                            expose_ports, primary_network_mode = self.context.client.call_sync(
                                'docker.container.query',
                                [('id', '=', ev['id'])],
                                {'select': ['expose_ports', 'primary_network_mode'], 'single': True}
                            )
                            if not expose_ports:
                                continue
                            if primary_network_mode != 'NAT':
                                continue

                            self.logger.debug('Redirecting container {0} ports on host firewall'.format(ev['id']))

                            mapped_ports = []

                            # Setup or destroy port redirection now, if needed
                            details = self.connection.inspect_container(ev['id'])
                            for i in get_docker_ports(details):
                                if i['host_port'] in mapped_ports:
                                    continue

                                if first_or_default(
                                    lambda r: r.proxy_ports[0] == i['host_port'],
                                    p.get_rules('rdr')
                                ):
                                    self.logger.warning('Cannot redirect port {0} to  {1}: already in use'.format(
                                        i['host_port'],
                                        ev['id']
                                    ))
                                    continue

                                rule = pf.Rule()
                                rule.label = 'container:{0}'.format(name)
                                rule.dst.port_range = [i['host_port'], 0]
                                rule.dst.port_op = pf.RuleOperator.EQ
                                rule.dst.address.ifname = self.context.default_if
                                rule.action = pf.RuleAction.RDR
                                rule.af = socket.AF_INET
                                rule.ifname = self.context.default_if
                                rule.natpass = True
                                rule.redirect_pool.append(pf.Address(
                                    address=self.vm.management_lease.lease.client_ip,
                                    netmask=ipaddress.ip_address('255.255.255.255')
                                ))
                                rule.proxy_ports = [i['host_port'], 0]
                                p.append_rule('rdr', rule)
                                mapped_ports.append(i['host_port'])

                            self.mapped_ports[ev['id']] = mapped_ports

                    if ev['Type'] == 'image':
                        image = first_or_default(
                            lambda i: ev['id'] in i['RepoTags'] if isinstance(i['RepoTags'], collections.Iterable) else False,
                            self.connection.images(),
                            default=ev
                        )
                        id = image.get('id') or image.get('Id')

                        def transform_action(action):
                            operation = actions.get(action, 'update')
                            if operation in ('create', 'delete'):
                                ref_cnt = self.context.client.call_sync(
                                    'containerd.docker.query_images',
                                    [('id', '=', id)],
                                    {'select': 'hosts', 'count': True}
                                )

                                if (ref_cnt and operation == 'delete') or (ref_cnt > 1 and operation == 'create'):
                                    return 'update'

                            return operation

                        self.context.client.emit_event('containerd.docker.image.changed', {
                            'operation': transform_action(ev['Action']),
                            'ids': [id]
                        })

                    if ev['Type'] == 'network':
                        netw_id = q.get(ev, 'Actor.ID')
                        cont_id = q.get(ev, 'Actor.Attributes.container')
                        operation = actions.get(ev['Action'], 'update')
                        if cont_id:
                            self.context.client.emit_event('containerd.docker.container.changed', {
                                'operation': operation,
                                'ids': [cont_id]
                            })
                        self.context.client.emit_event('containerd.docker.network.changed', {
                            'operation': operation,
                            'ids': [netw_id]
                        })

                self.logger.warning('Disconnected from Docker API endpoint on {0}'.format(self.vm.name))

            except BaseException as err:
                self.logger.error('Docker connection closed: {0}, retrying in 1 second'.format(str(err)), exc_info=True)
                time.sleep(1)

    def get_container_console(self, id):
        if id not in self.active_consoles:
            self.active_consoles[id] = ContainerConsole(self, id)

        return self.active_consoles[id]

    def shutdown(self):
        p = pf.PF()
        for container_ports in self.mapped_ports.values():
            for i in container_ports:
                rule = first_or_default(lambda r: r.proxy_ports[0] == i, p.get_rules('rdr'))
                if rule:
                    p.delete_rule('rdr', rule.index)


class ContainerConsole(object):
    def __init__(self, host, id):
        container = host.context.client.call_sync(
            'containerd.docker.query_containers',
            [('or', [('id', '=', id), ('exec_ids', 'contains', id)])],
            {'single': True}
        )
        raw_name = q.get(container, 'names.0')

        self.host = host
        self.context = self.host.context
        self.id = id
        self.is_exec = self.id in container['exec_ids']
        self.name = raw_name + 'Exec' if self.is_exec else raw_name
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.scrollback = None
        self.console_queues = []
        self.scrollback_t = None
        self.active = False
        self.lock = RLock()
        self.logger = logging.getLogger('Container:{0}'.format(self.name))

    def start_console(self):
        self.host.ready.wait()

        if self.is_exec:
            operation = dockerpty.pty.ExecOperation(self.host.connection, self.id)
            self.stdin = operation.sockets()
            self.stdout = self.stdin
        else:
            self.host.connection.start(container=self.id)
            operation = dockerpty.pty.RunOperation(self.host.connection, self.id)
            self.stdin, self.stdout, self.stderr = operation.sockets()
            self.stderr.set_blocking(False)

        self.stdout.set_blocking(False)

        self.scrollback = BinaryRingBuffer(SCROLLBACK_SIZE)
        self.scrollback_t = gevent.spawn(self.console_worker)
        self.active = True

    def stop_console(self):
        self.active = False
        self.host.ready.wait()
        self.stdin.write(b'\x10\x11')

        if isinstance(self.stdin, socket.SocketIO):
            self.stdin.fd.shutdown(socket.SHUT_RDWR)
            self.stdin.close()

        if not self.is_exec:
            if isinstance(self.stdout, socket.SocketIO):
                self.stdout.fd.shutdown(socket.SHUT_RDWR)
            if isinstance(self.stderr, socket.SocketIO):
                self.stderr.fd.shutdown(socket.SHUT_RDWR)
            self.stdout.close()
            self.stderr.close()

        self.scrollback_t.join()

    def console_register(self):
        with self.lock:
            queue = gevent.queue.Queue(4096)
            self.console_queues.append(queue)
            if not self.active:
                self.start_console()

            self.logger.debug('Registered a new console queue')
            return queue

    def console_unregister(self, queue):
        with self.lock:
            self.console_queues.remove(queue)

            self.logger.debug('Stopped a console queue')
            if not len(self.console_queues):
                self.logger.debug('Last console queue stopped. Detaching console')
                self.stop_console()

    def console_write(self, data):
        self.stdin.write(data)

    def console_worker(self):
        self.logger.debug('Opening console to {0}'.format(self.name))

        def write(data):
            if data == b'':
                data = StopIteration
            else:
                self.scrollback.push(data)

            try:
                for i in self.console_queues:
                    i.put(data, block=False)
            except:
                pass

        while True:
            try:
                fd_o = self.stdout.fileno()
                fd_e = None

                fd_list = [fd_o]
                if not self.is_exec:
                    fd_e = self.stderr.fileno()
                    fd_list.append(fd_e)

                r, w, x = select.select(fd_list, [], fd_list)

                if any(fd in x for fd in fd_list):
                    return

                if not any(fd in r for fd in fd_list):
                    continue

                if fd_o in r:
                    ch = self.stdout.read(1024)
                    write(ch)
                    if ch == b'':
                        return

                if fd_e in r:
                    ch = gevent.os.tp_read(fd_e)
                    write(ch)
                    if ch == b'':
                        return

            except (OSError, ValueError):
                return


class ManagementService(RpcService):
    def __init__(self, context):
        super(ManagementService, self).__init__()
        self.context = context
        self.retry_lock = RLock()

    @private
    def get_status(self, id):
        vm = self.context.vms.get(id)
        if not vm:
            return {'state': 'STOPPED'}

        mgmt_lease = vm.management_lease
        nat_lease = vm.nat_lease

        return {
            'state': vm.state.name,
            'health': vm.health,
            'vm_tools_available': vm.vmtools_ready,
            'management_lease': mgmt_lease.lease if mgmt_lease else None,
            'nat_lease': nat_lease.lease if nat_lease else None
        }

    @private
    def get_devices_status(self, id):
        res = {}
        vm = self.context.vms.get(id)
        if vm:
            if vm.devices:
                res.update({d['name']: 'CONNECTED' for d in vm.devices})

            if vm.dropped_devices:
                res.update({d: 'ERROR' for d in vm.dropped_devices})

        return res

    @private
    def start_vm(self, id, strict=False):
        container = self.context.datastore.get_by_id('vms', id)
        if not container:
            raise RpcException(errno.ENOENT, 'VM {0} not found'.format(id))

        if not vtx_enabled and not svm_features:
            raise RpcException(
                errno.ENOTSUP,
                'Cannot start VM {0} - CPU does not support virtualization'.format(container['name'])
            )

        if not unrestricted_guest and vtx_enabled and container['config']['bootloader'] != 'BHYVELOAD':
            raise RpcException(
                errno.ENOTSUP,
                'Cannot start VM {0} - only BHYVELOAD is supported for VT-x without unrestricted guest feature.'.format(
                    container['name']
                )
            )

        vm = VirtualMachine(self.context, container['name'])
        vm.id = container['id']
        vm.guest_type = container['guest_type']
        vm.config = container['config']
        vm.devices = container['devices']
        vm.autostart = q.get(container, 'config.autostart', False)

        if strict:
            invalid = list(vm.get_invalid_storage())
            if invalid:
                return invalid

        try:
            dropped_devices = vm.start()
        except BaseException as err:
            raise RpcException(errno.EFAULT, 'Cannot start VM: {0}'.format(err))

        if vm.config.get('docker_host', False):
            host = DockerHost(self.context, vm)
            vm.docker_host = host
            self.context.docker_hosts[id] = host

        with self.context.cv:
            self.context.vms[id] = vm
            self.context.cv.notify_all()

        return dropped_devices

    @private
    def retry_autostart(self, id):
        with self.retry_lock:
            if id in self.context.failed_autostart_vms:
                self.context.logger.debug(f'Retrying VM {id} autostart')
                if not self.start_vm(id, True):
                    self.context.failed_autostart_vms.remove(id)

    @private
    def stop_vm(self, id, force=False):
        container = self.context.datastore.get_by_id('vms', id)
        if not container:
            raise RpcException(errno.ENOENT, 'VM {0} not found'.format(id))

        self.context.logger.info('Stopping VM {0} ({1})'.format(container['name'], id))

        vm = self.context.vms.get(id)
        if not vm:
            return

        if vm.state == VirtualMachineState.STOPPED:
            raise RpcException(errno.EACCES, 'Container {0} is already stopped'.format(container['name']))

        if vm.config.get('docker_host', False):
            self.context.set_docker_api_forwarding(None)
            self.context.docker_hosts.pop(id, None)
            self.context.client.emit_event('containerd.docker.host.changed', {
                'operation': 'delete',
                'ids': [id]
            })

        vm.stop(force)
        with self.context.cv:
            self.context.vms.pop(id, None)
            self.context.cv.notify_all()

    @private
    def get_mgmt_allocations(self):
        return [i.__getstate__() for i in self.context.mgmt.allocations.values()]

    @private
    def get_netif_mappings(self, id):
        vm = self.context.vms.get(id)
        if not vm:
            raise RpcException(errno.ENOENT, 'VM {0} is not running'.format(id))

        return vm.interfaces_mappings

    @private
    def call_vmtools(self, id, fn, *args):
        vm = self.context.vms.get(id)
        if not vm:
            return

        return vm.call_vmtools(fn, *args)


class ConsoleService(RpcService):
    def __init__(self, context):
        super(ConsoleService, self).__init__()
        self.context = context

    @private
    def request_console(self, id):
        type = 'VM'
        vm = self.context.datastore.get_by_id('vms', id)
        if not vm:
            type = 'CONTAINER'
            container = self.context.client.call_sync(
                'containerd.docker.query_containers',
                [('or', [('id', '=', id), ('exec_ids', 'contains', id)])],
                {'single': True}
            )
            if not container:
                raise RpcException(errno.ENOENT, '{0} not found as either a VM or a container'.format(id))

        token = generate_id()
        self.context.tokens[token] = ConsoleToken(type, id)
        return token

    @private
    def request_webvnc_console(self, id):
        token = self.request_console(id)
        return f'/containerd/webvnc/{token}'


class DockerService(RpcService):
    def __init__(self, context):
        super(DockerService, self).__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.context = context

    def get_host_status(self, id):
        host = self.context.get_docker_host(id)

        try:
            info = host.connection.info()
            return {
                'os': info['OperatingSystem'],
                'hostname': info['Name'],
                'unique_id': info['ID'],
                'mem_total': info['MemTotal']
            }
        except:
            raise RpcException(errno.ENXIO, 'Cannot connect to host {0}'.format(id))

    def host_name_by_container_id(self, id):
        host = self.context.docker_host_by_container_id(id)
        return host.vm.name

    def host_name_by_network_id(self, id):
        host = self.context.docker_host_by_network_id(id)
        return host.vm.name

    def get_dhcp_lease(self, container_name, dockerhost_id, macaddr=None):
        dockerhost_name = self.context.get_docker_host(dockerhost_id).vm.name
        interfaces = self.context.client.call_sync('containerd.management.get_netif_mappings', dockerhost_id)
        interface = [i.get('target') for i in interfaces if i.get('mode') == 'BRIDGED']
        if not interface:
            raise RpcException(
                errno.EEXIST,
                'Failed to retrieve DHCP target interface, '
                'no BRIDGED interfaces found on docker host : {0}'.format(dockerhost_name)
            )
        if len(interface) > 1:
            raise RpcException(
                errno.EEXIST,
                'Failed to retrieve DHCP target interface, '
                'multiple BRIDGED interfaces found on docker host : {0}'.format(dockerhost_name)
            )
        c = dhcp.Client(interface[0], dockerhost_name+'.'+container_name)
        c.hwaddr = macaddr if macaddr else self.context.client.call_sync('vm.generate_mac')
        c.start()

        lease = c.wait_for_bind(timeout=30)
        if not lease or c.state != dhcp.State.BOUND:
            c.stop()
            raise RpcException(
                errno.EACCES,
                'Failed to obtain DHCP lease' + (' : {0}'.format(c.error) if c.error else '')
            )
        else:
            return lease.__getstate__()

    def labels_to_presets(self, labels=None):
        if not labels:
            labels = {}
        labels = normalize_docker_labels(labels)
        result = {
            'autostart': truefalse_to_bool(labels.get('org.freenas.autostart')),
            'bridge': {
                'dhcp': truefalse_to_bool(labels.get('org.freenas.dhcp')),
                'address': None
            },
            'capabilities_add': [],
            'capabilities_drop': [],
            'command': [],
            'expose_ports': truefalse_to_bool(labels.get('org.freenas.expose-ports-at-host')),
            'immutable': [],
            'interactive': truefalse_to_bool(labels.get('org.freenas.interactive')),
            'ports': [],
            'primary_network_mode': labels.get('org.freenas.primary-network-mode'),
            'privileged': truefalse_to_bool(labels.get('org.freenas.privileged')),
            'settings': [],
            'static_volumes': [],
            'upgradeable': truefalse_to_bool(labels.get('org.freenas.upgradeable')),
            'version': labels.get('org.freenas.version'),
            'volumes': [],
            'web_ui_path': labels.get('org.freenas.web-ui-path'),
            'web_ui_port': labels.get('org.freenas.web-ui-port'),
            'web_ui_protocol': labels.get('org.freenas.web-ui-protocol'),
        }

        if labels.get('org.freenas.immutable'):
            for l in labels.get('org.freenas.immutable').split(','):
                try:
                    result['immutable'].append(DOCKER_LABELS_MAP[l].get('preset'))
                except KeyError:
                    pass

        if labels.get('org.freenas.port-mappings'):
            for mapping in labels.get('org.freenas.port-mappings').split(','):
                m = re.match(r'^(\d+):(\d+)/(tcp|udp)$', mapping)
                if not m:
                    continue

                result['ports'].append({
                    'container_port': int(m.group(1)),
                    'host_port': int(m.group(2)),
                    'protocol': m.group(3).upper()
                })

        if labels.get('org.freenas.capabilities-add'):
            result['capabilities_add'] = labels['org.freenas.capabilities-add'].split(',')

        if labels.get('org.freenas.capabilities-drop'):
            result['capabilities_drop'] = labels['org.freenas.capabilities-drop'].split(',')

        if labels.get('org.freenas.command'):
            result['command'] = labels['org.freenas.command'].split(',')

        if labels.get('org.freenas.volumes'):
            try:
                j = loads(labels['org.freenas.volumes'])
            except ValueError:
                pass
            else:
                for vol in j:
                    if 'name' not in vol:
                        continue

                    result['volumes'].append({
                        'description': vol.get('descr'),
                        'container_path': vol['name'],
                        'readonly': truefalse_to_bool(vol.get('readonly'))
                    })

        if labels.get('org.freenas.static-volumes'):
            try:
                j = loads(labels['org.freenas.static-volumes'])
            except ValueError:
                pass
            else:
                for vol in j:
                    if any(v not in vol for v in ('container_path', 'host_path')):
                        continue

                    result['static_volumes'].append({
                        'container_path': vol.get('container_path'),
                        'host_path': vol.get('host_path'),
                        'readonly': truefalse_to_bool(vol.get('readonly'))
                    })

        if labels.get('org.freenas.settings'):
            try:
                j = loads(labels['org.freenas.settings'])
            except ValueError:
                pass
            else:
                for setting in j:
                    if 'env' not in setting:
                        continue

                    result['settings'].append({
                        'id': setting['env'],
                        'description': setting.get('descr'),
                        'optional': setting.get('optional', True)
                    })

        return result

    @generator
    def query_containers(self, filter=None, params=None):
        def normalize_names(names):
            for i in names:
                if i[0] == '/':
                    yield i[1:]
                else:
                    yield i

        def find_env(env, name):
            for i in env:
                n, v = i.split('=', maxsplit=1)
                if n == name:
                    return v

            return None

        result = []
        for host in self.context.iterate_docker_hosts():
            for container in host.connection.containers(all=True):
                obj = {}
                try:
                    details = host.connection.inspect_container(container['Id'])
                except NotFound:
                    continue

                host_config = q.get(details, 'HostConfig')
                net_mode = host_config.get('NetworkMode')
                bridge_enabled = net_mode == 'external'

                primary_network_mode = 'NAT'
                if bridge_enabled:
                    primary_network_mode = 'BRIDGED'
                if net_mode == 'host':
                    primary_network_mode = 'HOST'
                if net_mode == 'none':
                    primary_network_mode = 'NONE'

                networks = []
                hidden_builtin_networks = ('bridge', 'external', 'host', 'none')
                # Docker does not assign the <container>.NetworkSettings.Networks.<network>.NetworkID
                # untill the container is started, hence the below gymnastics to retrive the network id
                network_names = list(q.get(details, 'NetworkSettings.Networks', {}).keys())
                if network_names:
                    for n in host.connection.networks(names=network_names):
                        if n.get('Name') not in hidden_builtin_networks:
                            networks.append(n.get('Id'))
                labels = q.get(details, 'Config.Labels')
                environment = q.get(details, 'Config.Env')
                names = list(normalize_names(container['Names']))
                external = q.get(details, 'NetworkSettings.Networks.external')
                bridge_ipaddress = q.get(external, 'IPAMConfig.IPv4Address') if bridge_enabled else None
                bridge_macaddress = q.get(details, 'Config.MacAddress') if bridge_enabled else None
                presets = self.labels_to_presets(labels)
                settings = []
                web_ui_url = None
                command = q.get(details, 'Config.Cmd') or []
                if presets:
                    for i in presets.get('settings', []):
                        settings.append({
                            'id': i['id'],
                            'value': find_env(environment, i['id'])
                        })

                obj.update({
                    'id': container['Id'],
                    'image': container['Image'],
                    'image_id': container['ImageID'],
                    'name': names[0],
                    'names': names,
                    'command': command if isinstance(command, list) else [command],
                    'running': details['State'].get('Running', False),
                    'health': q.get(details, 'State.Health.Status'),
                    'host': host.vm.id,
                    'ports': list(get_docker_ports(details)),
                    'volumes': list(get_docker_volumes(details)),
                    'interactive': get_interactive(details),
                    'immutable': presets.get('immutable'),
                    'upgradeable': truefalse_to_bool(labels.get('org.freenas.upgradeable')),
                    'expose_ports': truefalse_to_bool(labels.get('org.freenas.expose-ports-at-host')),
                    'autostart': truefalse_to_bool(labels.get('org.freenas.autostart')),
                    'environment': environment,
                    'hostname': details['Config']['Hostname'],
                    'exec_ids': details['ExecIDs'] or [],
                    'bridge': {
                        'dhcp': truefalse_to_bool(labels.get('org.freenas.dhcp')),
                        'address': bridge_ipaddress,
                        'macaddress': bridge_macaddress,
                    },
                    'web_ui_url': web_ui_url,
                    'settings': settings,
                    'version': presets.get('version'),
                    'capabilities_add': host_config['CapAdd'] or [],
                    'capabilities_drop': host_config['CapDrop'] or [],
                    'privileged': host_config.get('Privileged', False),
                    'primary_network_mode': primary_network_mode,
                    'networks': networks,
                })
                if presets and presets.get('web_ui_protocol'):
                    try:
                        port = int(presets['web_ui_port'])
                    except ValueError:
                        port = ''
                    port_configuration = first_or_default(
                        lambda o: o['host_port'] == port and o['protocol'] == 'TCP',
                        obj['ports']
                    )

                    if port_configuration and q.get(obj, 'bridge.enable'):
                        port = port_configuration['container_port']

                    obj['web_ui_url'] = '{0}://{1}:{2}/{3}'.format(
                        presets['web_ui_protocol'],
                        bridge_ipaddress or socket.gethostname(),
                        port,
                        presets['web_ui_path']
                    )
                result.append(obj)

        return q.query(result, *(filter or []), stream=True, **(params or {}))

    @generator
    def query_networks(self, filter=None, params=None):
        result = []

        for host in self.context.iterate_docker_hosts():
            networks = host.connection.networks()
            networks_containers_map = {n['Name']: [] for n in networks}
            containers = host.connection.containers(all=True)
            for c in containers:
                network_names = list(q.get(c, 'NetworkSettings.Networks', {}).keys())
                for n in network_names:
                    try:
                        networks_containers_map[n].append(c['Id'])
                    except KeyError:
                        pass

            for network in networks:
                details = host.connection.inspect_network(network['Id'])
                config = q.get(details, 'IPAM.Config.0')

                result.append({
                    'id': details['Id'],
                    'name': details['Name'],
                    'driver': details['Driver'],
                    'subnet': config['Subnet'] if config else None,
                    'gateway': config.get('Gateway', None) if config else None,
                    'host': host.vm.id,
                    'containers': networks_containers_map[details['Name']]
                })

        return q.query(result, *(filter or []), stream=True, **(params or {}))

    @generator
    def query_images(self, filter=None, params=None):
        result = []
        for host in self.context.iterate_docker_hosts():
            for image in host.connection.images():
                old_img = first_or_default(lambda o: o['id'] == image['Id'], result)

                if old_img:
                    old_img['hosts'].append(host.vm.id)

                else:
                    presets = self.labels_to_presets(image['Labels'])
                    result.append({
                        'id': image['Id'],
                        'parent': image['ParentId'],
                        'names': image['RepoTags'] or [image['Id']],
                        'size': image['VirtualSize'],
                        'hosts': [host.vm.id],
                        'presets': presets,
                        'version': presets['version'],
                        'created_at': datetime.utcfromtimestamp(int(image['Created']))
                    })

        return q.query(result, *(filter or []), stream=True, **(params or {}))

    @generator
    def pull(self, name, host):
        host = self.context.get_docker_host(host)
        if not host:
            raise RpcException(errno.ENOENT, 'Docker host {0} not found'.format(host))

        try:
            for line in host.connection.pull(name, stream=True):
                yield json.loads(line.decode('utf-8'))
        except BaseException as err:
            raise RpcException(errno.EFAULT, 'Failed to pull image: {0}'.format(unpack_docker_error(err)))

    def delete_image(self, id, host):
        host = self.context.get_docker_host(host)
        try:
            host.connection.remove_image(image=id, force=True)
        except BaseException as err:
            raise RpcException(errno.EFAULT, 'Failed to remove image: {0}'.format(unpack_docker_error(err)))

    def start(self, id):
        host = self.context.docker_host_by_container_id(id)
        try:
            host.connection.start(container=id)
        except BaseException as err:
            raise RpcException(errno.EFAULT, 'Failed to start container: {0}'.format(unpack_docker_error(err)))

    def stop(self, id):
        host = self.context.docker_host_by_container_id(id)
        try:
            host.connection.stop(container=id)
        except BaseException as err:
            raise RpcException(errno.EFAULT, 'Failed to stop container: {0}'.format(unpack_docker_error(err)))

    def restart(self, id):
        host = self.context.docker_host_by_container_id(id)
        try:
            host.connection.restart(container=id)
        except BaseException as err:
            raise RpcException(errno.EFAULT, 'Failed to restart container: {0}'.format(unpack_docker_error(err)))

    def create_container(self, container):
        host = self.context.get_docker_host(container['host'])
        networking_config = None
        macaddr = None
        if not host:
            raise RpcException(errno.ENOENT, 'Docker host {0} not found'.format(container['host']))

        primary_network_mode = container.get('primary_network_mode')
        bridge_enabled = primary_network_mode == 'BRIDGED'
        dhcp_enabled = q.get(container, 'bridge.dhcp') if bridge_enabled else False
        labels = {
            'org.freenas.autostart': bool_to_truefalse(container.get('autostart')),
            'org.freenas.expose-ports-at-host': bool_to_truefalse(container.get('expose_ports')),
            'org.freenas.dhcp': bool_to_truefalse(dhcp_enabled),
        }

        port_bindings = {
            str(i['container_port']) + '/' + i.get('protocol', 'tcp').lower(): i['host_port'] for i in container['ports']
        }

        for v in container.get('volumes', []):
            if v.get('source') and v['source'] != 'HOST' and v['host_path'].startswith('/mnt'):
                raise RpcException(
                    errno.EINVAL,
                    '{0} is living inside /mnt, but its source is a {1} path'.format(
                        v['host_path'], v['source'].lower()
                    )
                )

        if bridge_enabled:
            macaddr = q.get(container, 'bridge.macaddress') or self.context.client.call_sync('vm.generate_mac')
            if dhcp_enabled:
                lease = self.get_dhcp_lease(container['name'], container['host'], macaddr)
                ipv4 = lease['client_ip']
            else:
                ipv4 = q.get(container, 'bridge.address')
            if not ipv4:
                raise RpcException(
                    errno.EINVAL,
                    'Either dhcp or static address must be selected for bridged container'
                )

            try:
                networking_config = host.connection.create_networking_config({
                    'external': host.connection.create_endpoint_config(
                        ipv4_address=ipv4
                    )
                })
            except BaseException as err:
                raise RpcException(errno.EFAULT, unpack_docker_error(err))

        caps_add = container.get('capabilities_add', [])
        caps_add.append('NET_ADMIN') if 'NET_ADMIN' not in caps_add else None
        caps_drop = container.get('capabilities_drop', [])

        network_mode = 'default'
        if bridge_enabled:
            network_mode = 'external'
        if primary_network_mode == 'HOST':
            network_mode = 'host'
        if primary_network_mode == 'NONE':
            network_mode = 'none'

        try:
            host_config = host.connection.create_host_config(
                port_bindings=port_bindings,
                binds={
                    i['host_path'].replace('/mnt', '/host'): {
                        'bind': i['container_path'],
                        'mode': 'ro' if i['readonly'] else 'rw'
                    } for i in container['volumes']
                    },
                privileged=container['privileged'],
                cap_add=caps_add,
                cap_drop=caps_drop,
                network_mode=network_mode
            )
        except BaseException as err:
            raise RpcException(errno.EFAULT, unpack_docker_error(err))

        create_args = {
            'name': container['name'],
            'image': container['image'],
            'ports': [(str(i['container_port']), i.get('protocol', 'tcp').lower()) for i in container['ports']],
            'volumes': [i['container_path'] for i in container['volumes']],
            'labels': labels,
            'networking_config': networking_config,
            'host_config': host_config,
        }

        if container.get('command'):
            create_args['command'] = container['command']

        if container.get('environment'):
            create_args['environment'] = container['environment']

        if container.get('interactive'):
            create_args['stdin_open'] = True
            create_args['tty'] = True

        if container.get('hostname'):
            create_args['hostname'] = container['hostname']

        if bridge_enabled:
            create_args['mac_address'] = macaddr

        try:
            host.connection.create_container(**create_args)
        except BaseException as err:
            raise RpcException(errno.EFAULT, unpack_docker_error(err))

    def create_network(self, network):
        host = self.context.get_docker_host(network.get('host'))
        if not host:
            raise RpcException(errno.ENOENT, 'Docker host {0} not found'.format(network.get('host')))

        create_args = {
            'name': network.get('name'),
            'driver': network.get('driver'),
        }

        if network.get('subnet'):
            create_args['ipam'] = docker.utils.create_ipam_config(
                pool_configs=[
                    docker.utils.create_ipam_pool(
                        subnet=network.get('subnet'),
                        gateway=network.get('gateway')
                    )
                ]
            )

        try:
            host.connection.create_network(**create_args)
        except BaseException as err:
            raise RpcException(
                errno.EFAULT,
                'Cannot create docker network {0}: {1}'.format(network.get('name'), unpack_docker_error(err))
            )

    def create_exec(self, id, command):
        host = self.context.docker_host_by_container_id(id)
        try:
            host.connection.start(container=id)
        except BaseException as err:
            raise RpcException(errno.EFAULT, 'Failed to start container: {0}'.format(unpack_docker_error(err)))
        try:
            exec = host.connection.exec_create(
                container=id,
                cmd=command,
                tty=True,
                stdin=True
            )
        except docker.errors.APIError:
            raise RpcException(errno.EINVAL, 'Cannot create exec. Container closed immediately after start')
        return exec['Id']

    def delete_container(self, id):
        try:
            host = self.context.docker_host_by_container_id(id)
        except RpcException as err:
            if err.code == errno.ENOENT:
                self.context.client.emit_event('containerd.docker.container.changed', {
                    'operation': 'delete',
                    'ids': [id]
                })
                return
        try:
            host.connection.remove_container(container=id, force=True)
        except BaseException as err:
            raise RpcException(errno.EFAULT, 'Failed to remove container: {0}'.format(unpack_docker_error(err)))

    def delete_network(self, id):
        try:
            host = self.context.docker_host_by_network_id(id)
        except RpcException as err:
            if err.code == errno.ENOENT:
                self.context.client.emit_event('containerd.docker.network.changed', {
                    'operation': 'delete',
                    'ids': [id]
                })
                return
        try:
            host.connection.remove_network(id)
        except BaseException as err:
            raise RpcException(errno.EFAULT, 'Failed to remove network: {0}'.format(unpack_docker_error(err)))

    def set_api_forwarding(self, hostid):
        if hostid in self.context.docker_hosts:
            try:
                self.context.set_docker_api_forwarding(None)
                self.context.set_docker_api_forwarding(hostid)
            except ValueError as err:
                raise RpcException(errno.EINVAL, err)
        else:
            self.context.set_docker_api_forwarding(None)

    def connect_container_to_network(self, container_id, network_id):
        host = self.context.docker_host_by_container_id(container_id)
        try:
            host.connection.connect_container_to_network(container_id, network_id)
        except BaseException as err:
            raise RpcException(
                errno.EFAULT,
                'Failed to connect container to network: {0}'.format(unpack_docker_error(err))
            )

        if not self.query_containers([('id', '=', container_id)], {'select': 'running', 'single': True}):
            # Docker does not transmit any event when stopped container is connected to network
            # so we must do this
            self.context.client.emit_event('containerd.docker.container.changed', {
                'operation': 'update',
                'ids': [container_id]
            })
            self.context.client.emit_event('containerd.docker.network.changed', {
                'operation': 'update',
                'ids': [network_id]
            })

    def disconnect_container_from_network(self, container_id, network_id):
        host = self.context.docker_host_by_container_id(container_id)
        try:
            host.connection.disconnect_container_from_network(container_id, network_id)
        except BaseException as err:
            raise RpcException(
                errno.EFAULT,
                'Failed to disconnect container from network: {0}'.format(unpack_docker_error(err))
            )

    def commit_image(self, container_id, new_name):
        host = self.context.docker_host_by_container_id(container_id)

        if '/' not in new_name:
            new_name = f'freenas/{new_name}'

        if ':' not in new_name:
            new_name = f'{new_name}:latest'

        repo, tag = new_name.split(':', 1)

        try:
            image = host.connection.commit(
                container=container_id,
                repository=repo,
                tag=tag
            )
        except BaseException as err:
            raise RpcException(errno.EFAULT, unpack_docker_error(err))

        image_details = first_or_default(lambda i: i['Id'] == image['Id'], host.connection.images(), {})
        return image_details['RepoTags'][0] or image['Id']

    def diff_container(self, container_id):
        host = self.context.docker_host_by_container_id(container_id)
        try:
            return host.connection.diff(container_id)
        except BaseException as err:
            raise RpcException(errno.EFAULT, unpack_docker_error(err))


class ServerResource(Resource):
    def __init__(self, apps=None, context=None):
        super(ServerResource, self).__init__(apps)
        self.context = context

    def __call__(self, environ, start_response):
        environ = environ
        current_app = self._app_by_path(environ['PATH_INFO'], 'wsgi.websocket' in environ)

        if current_app is None:
            raise Exception("No apps defined")

        if 'wsgi.websocket' in environ:
            ws = environ['wsgi.websocket']
            current_app = current_app(ws, self.context)
            current_app.ws = ws  # TODO: needed?
            current_app.handle()

            return None
        else:
            return current_app(environ, start_response)


class ConsoleConnection(WebSocketApplication, EventEmitter):
    BUFSIZE = 1024

    def __init__(self, ws, context):
        super(ConsoleConnection, self).__init__(ws)
        self.context = context
        self.logger = logging.getLogger('ConsoleConnection')
        self.authenticated = False
        self.console_queue = None
        self.console_provider = None
        self.rd = None
        self.wr = None
        self.inq = Queue()

    def worker(self):
        self.logger.info('Opening console to %s...', self.console_provider.name)

        def read_worker():
            for data in self.console_queue:
                if data is None:
                    return

                try:
                    self.ws.send(data.replace(b'\n\n', b'\r\n'))
                except WebSocketError as err:
                    self.logger.info('WebSocket connection terminated: {0}'.format(str(err)))
                    return

            self.ws.close()

        def write_worker():
            for i in self.inq:
                try:
                    self.console_provider.console_write(i)
                except BrokenPipeError:
                    return

        self.wr = gevent.spawn(write_worker)
        self.rd = gevent.spawn(read_worker)
        gevent.joinall([self.rd, self.wr])

    def on_open(self, *args, **kwargs):
        pass

    def on_close(self, *args, **kwargs):
        self.inq.put(StopIteration)
        if self.console_queue:
            self.console_queue.put(StopIteration)

        if self.console_provider:
            self.console_provider.console_unregister(self.console_queue)

    def on_message(self, message, *args, **kwargs):
        if message is None:
            return

        if not self.authenticated:
            if isinstance(message, bytes):
                message = message.decode('utf-8')
            message = json.loads(message)

            if type(message) is not dict:
                return

            if 'token' not in message:
                return

            cid = self.context.tokens.get(message['token'])
            if not cid:
                self.ws.send(json.dumps({'status': 'failed'}))
                return

            self.authenticated = True

            if cid.type == 'CONTAINER':
                container = self.context.client.call_sync(
                    'containerd.docker.query_containers',
                    [('or', [('id', '=', cid.id), ('exec_ids', 'contains', cid.id)])],
                    {'single': True}
                )

                if container:
                    docker_host = self.context.docker_host_by_container_id(container['id'])
                    self.console_provider = docker_host.get_container_console(cid.id)

            if cid.type == 'VM':
                with self.context.cv:
                    if not self.context.cv.wait_for(lambda: cid.id in self.context.vms, timeout=30):
                        return
                    self.console_provider = self.context.vms[cid.id]

            self.console_queue = self.console_provider.console_register()
            self.ws.send(json.dumps({'status': 'ok'}))
            self.ws.send(self.console_provider.scrollback.read())

            gevent.spawn(self.worker)
            return

        if isinstance(message, str):
            message = message.encode('utf-8')

        for i in message:
            i = bytes([i])
            if i == '\r':
                i = '\n'
            self.inq.put(i)


class VncConnection(WebSocketApplication, EventEmitter):
    def __init__(self, ws, context):
        super(VncConnection, self).__init__(ws)
        self.context = context
        self.logger = logging.getLogger('VncConnection')
        self.cfd = None
        self.vm = None

    @classmethod
    def protocol_name(cls):
        return 'binary'

    def on_open(self, *args, **kwargs):
        qs = dict(urllib.parse.parse_qsl(self.ws.environ['QUERY_STRING']))
        token = qs.get('token')
        if not token:
            self.ws.close()
            return

        cid = self.context.tokens.get(token)
        if not cid:
            self.logger.warn('Invalid token {0}, closing connection'.format(token))
            self.ws.close()
            return

        def read():
            buffer = bytearray(4096)
            while True:
                n = self.cfd.recv_into(buffer)
                if n == 0:
                    self.ws.close()
                    return

                self.ws.send(buffer[:n])

        self.vm = self.context.vms[cid.id]
        self.logger.info('Opening VNC console to {0} (token {1})'.format(self.vm.name, token))

        self.cfd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        self.cfd.connect(self.vm.vnc_socket)
        gevent.spawn(read)

    def on_message(self, message, *args, **kwargs):
        if message is None:
            self.ws.close()
            return

        self.cfd.send(message)

    def on_close(self, *args, **kwargs):
        self.cfd.shutdown(socket.SHUT_RDWR)


class Main(object):
    def __init__(self):
        self.client = None
        self.datastore = None
        self.configstore = None
        self.config = None
        self.mgmt = None
        self.nat = None
        self.vm_started = Event()
        self.vms = {}
        self.failed_autostart_vms = []
        self.docker_hosts = {}
        self.tokens = {}
        self.logger = logging.getLogger('containerd')
        self.bridge_interface = None
        self.used_nmdms = []
        self.network_initialized = False
        self.nat_addrs = ()
        self.ec2 = None
        self.default_if = None
        self.proxy_server = ReverseProxyServer()
        self.cv = Condition()

    def init_datastore(self):
        try:
            self.datastore = get_datastore(self.config)
        except DatastoreException as err:
            self.logger.error('Cannot initialize datastore: %s', str(err))
            sys.exit(1)

        self.configstore = ConfigStore(self.datastore)

    def allocate_nmdm(self):
        for i in range(0, 255):
            if i not in self.used_nmdms:
                self.used_nmdms.append(i)
                return i

    def release_nmdm(self, index):
        self.used_nmdms.remove(index)

    def connect(self):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('containerd')
                self.client.enable_server()
                self.client.rpc.streaming_enabled = True
                self.client.register_event_handler('network.changed', lambda args: self.init_nat())
                self.client.register_service('containerd.management', ManagementService(self))
                self.client.register_service('containerd.console', ConsoleService(self))
                self.client.register_service('containerd.docker', DockerService(self))
                self.client.register_service('containerd.debug', DebugService(gevent=True, builtins={"context": self}))
                self.client.resume_service('containerd.management')
                self.client.resume_service('containerd.console')
                self.client.resume_service('containerd.docker')
                self.client.resume_service('containerd.debug')

                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

    def init_dispatcher(self):
        def on_error(reason, **kwargs):
            if reason in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
                self.logger.warning('Connection to dispatcher lost')
                self.connect()

        self.client = Client()
        self.client.on_error(on_error)
        self.connect()

    def init_mgmt(self):
        if self.network_initialized:
            return

        mgmt_subnet = ipaddress.ip_network(self.configstore.get('container.network.management'))
        nat_subnet = ipaddress.ip_network(self.configstore.get('container.network.nat'))

        # Check if mgmt or nat subnets collide with any other subnets in the system
        for iface in self.client.call_sync('network.interface.query'):
            for alias in q.get(iface, 'status.aliases'):
                if alias['type'] != 'INET':
                    continue

                alias = ipaddress.ip_interface('{0}/{1}'.format(alias['address'], alias['netmask']))
                if alias.network.overlaps(mgmt_subnet):
                    raise RuntimeError('Subnet {0} on interface {1} overlaps with VM management subnet'.format(
                        alias.network,
                        iface['id'],
                    ))

                if alias.network.overlaps(nat_subnet):
                    raise RuntimeError('Subnet {0} on interface {1} overlaps with VM NAT subnet'.format(
                        alias.network,
                        iface['id'],
                    ))

        mgmt_addr = ipaddress.ip_interface('{0}/{1}'.format(next(mgmt_subnet.hosts()), mgmt_subnet.prefixlen))
        self.mgmt = ManagementNetwork(self, MGMT_INTERFACE, mgmt_addr)
        self.mgmt.up()
        self.mgmt.bridge_if.add_address(netif.InterfaceAddress(
            netif.AddressFamily.INET,
            ipaddress.ip_interface('169.254.169.254/32')
        ))

        nat_addr = ipaddress.ip_interface('{0}/{1}'.format(next(nat_subnet.hosts()), nat_subnet.prefixlen))
        self.nat = ManagementNetwork(self, NAT_INTERFACE, nat_addr)
        self.nat.up()

        self.network_initialized = True
        self.nat_addrs = (mgmt_addr, nat_addr)
        self.init_nat()

    def init_nat(self):
        self.default_if = self.client.call_sync('networkd.configuration.get_default_interface')
        if not self.default_if:
            self.logger.warning('No default route interface; not configuring NAT')
            return

        p = pf.PF()

        for addr in self.nat_addrs:
            # Try to find and remove existing NAT rules for the same subnet
            oldrule = first_or_default(
                lambda r: r.src.address.address == addr.network.network_address,
                p.get_rules('nat')
            )

            if oldrule:
                p.delete_rule('nat', oldrule.index)

            rule = pf.Rule()
            rule.src.address.address = addr.network.network_address
            rule.src.address.netmask = addr.netmask
            rule.action = pf.RuleAction.NAT
            rule.af = socket.AF_INET
            rule.ifname = self.default_if
            rule.redirect_pool.append(pf.Address(ifname=self.default_if))
            rule.proxy_ports = [50001, 65535]
            p.append_rule('nat', rule)

        try:
            p.enable()
        except OSError as err:
            if err.errno != errno.EEXIST:
                raise err

        # Last, but not least, enable IP forwarding in kernel
        try:
            sysctl.sysctlbyname('net.inet.ip.forwarding', new=1)
        except OSError as err:
            raise err

    def init_dhcp(self):
        pass

    def vm_by_mgmt_mac(self, mac):
        for i in self.vms.values():
            for tapmac in i.tap_interfaces.values():
                if tapmac == mac:
                    return i

        return None

    def vm_by_mgmt_ip(self, ip):
        for i in self.mgmt.allocations.values():
            if i.lease.client_ip == ip:
                return i.vm()

    def docker_host_by_container_id(self, id):
        for host in self.docker_hosts.values():
            try:
                if host.connection.containers(all=True, quiet=True, filters={'id': id}):
                    host.ready.wait()
                    return host
            except:
                pass

            continue

        raise RpcException(errno.ENOENT, 'Container {0} not found'.format(id))

    def docker_host_by_network_id(self, id):
        for host in self.docker_hosts.values():
            for n in host.connection.networks():
                if n['Id'] == id:
                    host.ready.wait()
                    return host

        raise RpcException(errno.ENOENT, 'Network {0} not found'.format(id))

    def get_docker_host(self, id):
        host = self.docker_hosts.get(id)
        if not host:
            raise RpcException(errno.ENOENT, 'Docker host {0} not found'.format(id))

        host.ready.wait()
        return host

    def iterate_docker_hosts(self):
        for host in self.docker_hosts.values():
            host.ready.wait()
            yield host

    def set_docker_api_forwarding(self, hostid):
        p = pf.PF()
        if hostid:
            if first_or_default(lambda r: r.proxy_ports[0] == 2375, p.get_rules('rdr')):
                raise ValueError('Cannot redirect Docker API to {0}: port 2375 already in use'.format(hostid))

            rule = pf.Rule()
            rule.label = 'Docker API'
            rule.dst.port_range = [2375, 0]
            rule.dst.port_op = pf.RuleOperator.EQ
            rule.action = pf.RuleAction.RDR
            rule.af = socket.AF_INET
            rule.ifname = self.default_if
            rule.natpass = True

            host = self.get_docker_host(hostid)

            rule.redirect_pool.append(pf.Address(
                address=host.vm.management_lease.lease.client_ip,
                netmask=ipaddress.ip_address('255.255.255.255')
            ))
            rule.proxy_ports = [2375, 0]
            p.append_rule('rdr', rule)

        else:
            rule = first_or_default(lambda r: r.proxy_ports[0] == 2375, p.get_rules('rdr'))
            if rule:
                p.delete_rule('rdr', rule.index)

    def die(self):
        self.logger.warning('Exiting')
        self.set_docker_api_forwarding(None)
        greenlets = []
        for i in self.vms.values():
            greenlets.append(gevent.spawn(i.stop, False))

        gevent.joinall(greenlets, timeout=30)
        self.client.disconnect()
        sys.exit(0)

    def dispatcher_error(self, error):
        self.die()

    def init_autostart(self):
        for id, autostart in self.client.call_sync('vm.query', [], {'select': ('id', 'config.autostart')}):
            if autostart:
                if self.client.call_sync('containerd.management.start_vm', id, True):
                    self.failed_autostart_vms.append(id)

    def init_docker_collections(self):
        self.client.call_sync(
            'networkd.configuration.wait_for_default_interface',
            600,
            timeout=600
        )
        collections = set(self.client.call_sync('docker.collection.query', [], {'select': 'collection'}))
        for c in collections:
            try:
                self.client.call_sync('docker.image.update_collection', c, True, timeout=600)
            except RpcException as err:
                self.logger.error(f'Couldn\'t init {c} collection. Error: {err}', exc_info=True)

    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', metavar='CONFIG', default=DEFAULT_CONFIGFILE, help='Middleware config file')
        parser.add_argument('-p', type=int, metavar='PORT', default=5500, help="WebSockets server port")
        args = parser.parse_args()
        configure_logging('containerd', 'DEBUG')
        setproctitle('containerd')

        gevent.signal(signal.SIGTERM, self.die)
        gevent.signal(signal.SIGQUIT, self.die)

        # Load pf kernel module
        try:
            kld.kldload('/boot/kernel/pf.ko')
        except OSError as err:
            if err.errno != errno.EEXIST:
                self.logger.error('Cannot load PF module: %s', str(err))
                self.logger.error('NAT unavailable')

        os.makedirs('/var/run/containerd', exist_ok=True)

        self.config = args.c
        self.init_datastore()
        self.init_dispatcher()
        gevent.spawn(self.init_autostart)
        gevent.spawn(self.init_docker_collections)
        self.logger.info('Started')

        global vtx_enabled, unrestricted_guest, svm_features
        hw_capabilities = self.client.call_sync('vm.get_hw_vm_capabilities')

        vtx_enabled = hw_capabilities['vtx_enabled']
        svm_features = hw_capabilities['svm_features']
        unrestricted_guest = hw_capabilities['unrestricted_guest']

        # WebSockets server
        kwargs = {}
        s4 = WebSocketServer(('0.0.0.0', args.p), ServerResource({
            '/console': ConsoleConnection,
            '/vnc': VncConnection,
            '/webvnc/[\w]+': app
        }, context=self), **kwargs)

        s6 = WebSocketServer(('::', args.p), ServerResource({
            '/console': ConsoleConnection,
            '/vnc': VncConnection,
            '/webvnc/[\w]+': app
        }, context=self), **kwargs)

        serv_threads = [gevent.spawn(s4.serve_forever), gevent.spawn(s6.serve_forever)]
        checkin()
        gevent.joinall(serv_threads)


if __name__ == '__main__':
    m = Main()
    m.main()
