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

import ipaddress
import errno
import os
import copy
import random
import gzip
import hashlib
import gevent
import uuid
import pygit2
import urllib.request
import urllib.parse
import urllib.error
import shutil
import tarfile
import logging
import datetime
import tempfile
from cache import EventCacheStore
from bsd.copy import copytree
from bsd import sysctl
from task import Provider, Task, ProgressTask, VerifyException, TaskException, query, TaskWarning, TaskDescription
from task import ValidationException
from datastore.config import ConfigNode
from freenas.dispatcher import Password
from freenas.dispatcher.jsonenc import loads, dumps
from freenas.dispatcher.rpc import RpcException, generator
from freenas.dispatcher.rpc import SchemaHelper as h, description, accepts, returns, private
from freenas.utils import first_or_default, normalize, deep_update, process_template, in_directory
from freenas.utils import sha256, exclude, query as q
from utils import save_config, load_config, delete_config
from freenas.utils.decorators import throttle
from freenas.utils.lazy import lazy
from debug import AttachRPC, AttachDirectory


VM_OUI = '02:a0:98'  # NetApp
VM_ROOT = '/vm'
CACHE_ROOT = '/.vm_cache'
BLOCKSIZE = 65536
MAX_VM_TOOLS_FILE_SIZE = 102400
CONFIG_VERSION = 100000
logger = logging.getLogger(__name__)
templates = None


@description('Provides information about VMs')
class VMProvider(Provider):
    @query('Vm')
    @generator
    def query(self, filter=None, params=None):
        def extend(obj):
            def read_readme():
                try:
                    root = self.dispatcher.call_sync('vm.get_vm_root', obj['id'])
                    if os.path.isdir(root):
                        readme = get_readme(root)
                        if readme:
                            with open(readme, 'r') as readme_file:
                                return readme_file.read()
                except (RpcException, OSError):
                    pass

            def get_disk_size(id, target, name, type):
                size = 0
                try:
                    path = self.dispatcher.call_sync('vm.get_device_path', id, name, False)
                    dir = os.path.dirname(path)

                    device = first_or_default(
                        lambda o: o['path'] == path and o['type'] == type,
                        self.dispatcher.call_sync('vm.datastore.list', type, target, dir)
                    )
                    if device:
                        size = device['size']
                except RpcException:
                    pass

                return size

            def get_status():
                vm_id = obj['id']
                if obj['target'] in datastores and os.path.isdir(self.dispatcher.call_sync('vm.get_vm_root', vm_id)):
                    return self.dispatcher.call_sync('containerd.management.get_status', vm_id)
                else:
                    return {'state': 'ORPHANED'}

            def get_devices_status():
                vm_id = obj['id']
                try:
                    return self.dispatcher.call_sync('containerd.management.get_devices_status', vm_id)
                except RpcException:
                    return {}

            obj['status'] = lazy(get_status)
            obj['config']['readme'] = lazy(read_readme)
            devices_status = get_devices_status()
            for d in obj['devices']:
                d['status'] = devices_status.get(d.get('name'), 'UNKNOWN')
                if d['type'] == 'DISK':
                    type = q.get(d, 'properties.target_type')
                    q.set(d, 'properties.size', lazy(get_disk_size, obj['id'], obj['target'], d['name'], type))

            vnc_password = q.get(obj, 'config.vnc_password')
            if vnc_password:
                q.set(obj, 'config.vnc_password', Password(vnc_password))

            return obj

        datastores = list(self.dispatcher.call_sync('vm.datastore.query', [], {'select': 'id'}))

        return q.query(
            self.datastore.query_stream('vms', callback=extend),
            *(filter or []),
            stream=True,
            **(params or {})
        )

    @private
    @accepts(str, bool)
    @returns(h.one_of(str, None))
    def get_vm_root(self, vm_id, local=True):
        vm = self.datastore.get_by_id('vms', vm_id)
        if not vm:
            return None

        if local:
            return self.dispatcher.call_sync(
                'vm.datastore.get_filesystem_path',
                vm['target'],
                get_vm_path(vm['name'])
            )
        else:
            return get_vm_path(vm['name'])

    @accepts(str, str, bool)
    @returns(h.one_of(str, None))
    def get_device_path(self, vm_id, device_name, local=True):
        def return_path(target, path):
            if local:
                return self.dispatcher.call_sync(
                    'vm.datastore.get_filesystem_path',
                    target,
                    path
                )
            else:
                return path

        vm = self.datastore.get_by_id('vms', vm_id)
        if not vm:
            return None

        device = first_or_default(lambda d: d['name'] == device_name, vm['devices'])
        if not device:
            return None

        if device['type'] == 'DISK':
            target_type = q.get(device, 'properties.target_type')
            target_path = q.get(device, 'properties.target_path')

            if target_type == 'DISK':
                return self.dispatcher.call_sync(
                    'disk.query',
                    [('id', '=', target_path)],
                    {'single': True, 'select': 'path'}
                )

            return return_path(vm['target'], os.path.join(VM_ROOT, vm['name'], target_path))

        if device['type'] == 'CDROM':
            path = device['properties']['path']
            if os.path.isabs(path):
                if local:
                    return path
                else:
                    return None
            else:
                return return_path(vm['target'], path)

        if device['type'] == 'VOLUME':
            if device['properties'].get('auto'):
                return return_path(vm['target'], os.path.join(VM_ROOT, vm['name'], device['name']))

            if local:
                return device['properties']['destination']
            else:
                return None

    @private
    @description("Get VMs dependent on provided filesystem path")
    @accepts(str, bool, bool)
    @returns(h.array(h.ref('Vm')))
    def get_dependencies(self, path, enabled_only=True, recursive=True):
        result = []

        if enabled_only:
            vms = self.datastore.query_stream('vms', ('enabled', '=', True))
        else:
            vms = self.datastore.query_stream('vms')

        for i in vms:
            target_path = self.get_vm_root(i['id'])
            if recursive:
                if in_directory(target_path, path):
                    result.append(i)
            else:
                if target_path == path:
                    result.append(i)

        return result

    @private
    @returns(str)
    def generate_mac(self):
        return VM_OUI + ':' + ':'.join('{0:02x}'.format(random.randint(0, 255)) for _ in range(0, 3))

    @private
    @accepts(str)
    @returns(h.tuple(str, h.array(str)))
    def get_reserved_storage(self, id):
        vm_snapshots = self.dispatcher.call_sync('vm.snapshot.query', [('parent.id', '=', id)])

        reserved_storage = []
        datastore = ''
        for snap in vm_snapshots:
            datastore, storage = self.dispatcher.call_sync('vm.snapshot.get_dependent_storage', snap['id'])
            reserved_storage.extend(storage)

        return datastore, list(set(reserved_storage))

    @private
    @accepts(str)
    @returns(h.tuple(str, h.array(str)))
    def get_dependent_storage(self, id):
        vm = self.dispatcher.call_sync('vm.query', [('id', '=', id)], {'single': True})
        if not vm:
            raise RpcException(errno.ENOENT, 'VM {0} does not exist'.format(id))

        devices = vm['devices']

        root_dir = self.dispatcher.call_sync('vm.get_vm_root', id, False)

        dependent_storage = [root_dir]
        for d in devices:
            if d['type'] in ('DISK', 'VOLUME'):
                dependent_storage.append(os.path.join(root_dir, d['name']))

        return vm['target'], dependent_storage

    @accepts(str)
    @returns(h.ref('VmGuestInfo'))
    def get_guest_info(self, id):
        interfaces = self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'network.interfaces')
        loadavg = self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'system.loadavg')
        try:
            version = self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'system.vm_tools_version')
        except RpcException:
            version = None

        if interfaces and loadavg:
            return {
                'interfaces': interfaces,
                'load_avg': list(loadavg),
                'version': version
            }

    @accepts(str, str)
    @returns(h.object())
    def guest_ls(self, id, path):
        return list(self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'file.ls', path))

    @accepts(str, str)
    def guest_get(self, id, path):
        return self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'file.get', path)

    @accepts(str, str, bytes)
    def guest_put(self, id, path, file):
        return self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'file.put', path, file)

    @accepts(str, str, h.array(str))
    def guest_exec(self, id, cmd, args):
        return self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'system.exec', cmd, args)

    @accepts(str)
    @returns(str)
    def request_serial_console(self, id):
        return self.dispatcher.call_sync('containerd.console.request_console', id)

    @accepts(str)
    @returns(str)
    def request_webvnc_console(self, id):
        return self.dispatcher.call_sync('containerd.console.request_webvnc_console', id)

    @returns(h.ref('VmHwCapabilites'))
    def get_hw_vm_capabilities(self):
        hw_capabilities = {'vtx_enabled': False, 'svm_features': False, 'unrestricted_guest': False}
        try:
            if sysctl.sysctlbyname('hw.vmm.vmx.initialized'):
                hw_capabilities['vtx_enabled'] = True

            if sysctl.sysctlbyname('hw.vmm.svm.features') > 0:
                hw_capabilities['svm_features'] = True

            if sysctl.sysctlbyname('hw.vmm.vmx.cap.unrestricted_guest'):
                hw_capabilities['unrestricted_guest'] = True
        except OSError:
            pass
        return hw_capabilities


@description('Provides information about VM snapshots')
class VMSnapshotProvider(Provider):
    @query('VmSnapshot')
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('vm.snapshots', *(filter or []), **(params or {}))

    @private
    @accepts(str)
    @returns(h.tuple(str, h.array(str)))
    def get_dependent_storage(self, id):
        snapshot = self.dispatcher.call_sync('vm.snapshot.query', [('id', '=', id)], {'single': True})
        if not snapshot:
            raise RpcException(errno.ENOENT, 'VM snapshot {0} does not exist'.format(id))

        devices = snapshot['parent']['devices']

        root_dir = self.dispatcher.call_sync('vm.get_vm_root', snapshot['parent']['id'], False)

        dependent_storage = [root_dir]
        for d in devices:
            if d['type'] in ('DISK', 'VOLUME'):
                dependent_storage.append(os.path.join(root_dir, d['name']))

        return snapshot['parent']['target'], dependent_storage


@description('Provides information about VM templates')
class VMTemplateProvider(Provider):
    @query('Vm')
    @generator
    def query(self, filter=None, params=None):
        def extend(obj):
            obj['template']['cached_on'] = []
            for d, c in cache_dirs:
                if os.path.isdir(os.path.join(c, obj['template']['name'])):
                    obj['template']['cached_on'].append(d)

            return obj

        gevent.spawn(self.update)

        datastores = self.dispatcher.call_sync('vm.datastore.query', [], {'select': 'id'})
        cache_dirs = []
        for d in datastores:
            try:
                cache_dirs.append((d, self.dispatcher.call_sync('vm.datastore.get_filesystem_path', d, CACHE_ROOT)))
            except RpcException:
                pass

        return q.query(
            q.filter_and_map(extend, templates.validvalues()),
            *(filter or []),
            stream=True,
            **(params or {})
        )

    @private
    def update(self, force=False):
        fetch_lock = self.dispatcher.get_lock('vm_templates')
        templates_updated = False
        with fetch_lock:
            try:
                if force:
                    self.dispatcher.call_task_sync('vm.template.fetch')
                    templates_updated = True
                else:
                    templates_updated = fetch_templates(self.dispatcher)
            except RpcException:
                pass

        if not templates_updated:
            return

        result = {}
        templates_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_templates')

        ids = []
        for root, dirs, files in os.walk(templates_dir):
            if 'template.json' in files:
                with open(os.path.join(root, 'template.json'), encoding='utf-8') as template_file:
                    try:
                        template = loads(template_file.read())
                        readme = get_readme(root)
                        if readme:
                            with open(readme, 'r') as readme_file:
                                template['template']['readme'] = readme_file.read()
                        template['template']['path'] = root
                        template['template']['cached'] = False
                        template['template']['source'] = root.split('/')[-2]
                        if template['template']['source'] == 'ipfs':
                            with open(os.path.join(root, 'hash')) as ipfs_hash:
                                template['template']['hash'] = ipfs_hash.read()

                        total_fetch_size = 0
                        for file in template['template']['fetch']:
                            total_fetch_size += file.get('size', 0)

                        template['template']['fetch_size'] = total_fetch_size

                        template['template']['template_version'] = str(
                            template['template']['updated_at'].date()).replace('-', '')

                        hash = hashlib.sha256(
                            '{}{}'.format(
                                q.get(template, 'template.source'),
                                q.get(template, 'template.name')
                            ).encode('utf-8')
                        )
                        id = hash.hexdigest()
                        template['id'] = id

                        result[id] = template
                        ids.append(id)
                    except ValueError:
                        pass

            removed = templates.query(('id', 'nin', ids), {'select': 'id'})
            templates.update(**result)
            if removed:
                templates.remove_many(removed)


class VMConfigProvider(Provider):
    @returns(h.ref('VmConfig'))
    def get_config(self):
        return ConfigNode('container', self.configstore).__getstate__()


@accepts(h.ref('VmConfig'))
class VMConfigUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating VM subsystem configuration"

    def describe(self, updated_fields):
        return TaskDescription("Updating VM subsystem configuration")

    def verify(self, updated_fields):
        errors = ValidationException()
        if 'network' in updated_fields:
            for k, v in updated_fields['network'].items():
                try:
                    net = ipaddress.ip_network(v)
                    if net.prefixlen != 24:
                        raise ValueError('Prefix length must be 24')
                except ValueError as err:
                    errors.add((0, 'network', k), str(err))

        if errors:
            raise errors

        return ['system']

    def run(self, updated_fields):
        node = ConfigNode('container', self.configstore)
        node.update(updated_fields)
        if first_or_default(lambda k: k != 'additional_templates', updated_fields):
            self.add_warning(TaskWarning(errno.EBUSY, 'Changes will be effective on next reboot'))

        if 'additional_templates' in updated_fields:
            with self.dispatcher.get_lock('vm_templates'):
                valid_sources = updated_fields['additional_templates'] + ['github', 'ipfs']
                templates_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_templates')
                for t in os.listdir(templates_dir):
                    if t not in valid_sources:
                        shutil.rmtree(os.path.join(templates_dir, t))

                self.dispatcher.call_async('vm.template.update', None, True)


class VMBaseTask(ProgressTask):
    def __init__(self, dispatcher):
        super(VMBaseTask, self).__init__(dispatcher)
        self.vm_root_dir = None

    def init_root_dir(self, vm):
        self.vm_root_dir = get_vm_path(vm['name'])

        if not self.dispatcher.call_sync('vm.datastore.directory_exists', vm['target'], VM_ROOT):
            # Create VM root
            self.run_subtask_sync('vm.datastore.directory.create', vm['target'], VM_ROOT)

        try:
            self.run_subtask_sync('vm.datastore.directory.create', vm['target'], self.vm_root_dir)
        except RpcException:
            raise TaskException(
                errno.EACCES,
                'Directory {0} already exists on {1} datastore. Maybe you meant to import a VM?'.format(
                    self.vm_root_dir,
                    vm['target']
                )
            )

    def init_files(self, vm, progress_cb=None):
        if progress_cb:
            progress_cb(0, 'Initializing VM files')
        template = vm.get('template')
        if not template:
            return

        dest_root = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', vm['target'], self.vm_root_dir)
        try:
            shutil.copy(os.path.join(template['path'], 'README.md'), dest_root)
        except OSError:
            pass

        if template.get('files'):
            source_root = os.path.join(template['path'], 'files')
            datastore = vm['target']
            files_datastore_path = os.path.join(self.vm_root_dir, 'files')

            self.run_subtask_sync(
                'vm.datastore.directory.create',
                datastore,
                files_datastore_path
            )
            files_root = self.dispatcher.call_sync(
                'vm.datastore.get_filesystem_path',
                datastore,
                files_datastore_path
            )

            for root, dirs, files in os.walk(source_root):
                r = os.path.relpath(root, source_root)

                for f in files:
                    name, ext = os.path.splitext(f)
                    if ext == '.in':
                        process_template(os.path.join(root, f), os.path.join(files_root, r, name), **{
                            'VM_ROOT': dest_root
                        })
                    else:
                        shutil.copy(os.path.join(root, f), os.path.join(files_root, r, f))

                for d in dirs:
                    os.mkdir(os.path.join(files_root, r, d))

            if template.get('fetch'):
                cloning_supported = self.dispatcher.call_sync(
                    'vm.datastore.query',
                    [('id', '=', datastore)],
                    {'single': True, 'select': 'capabilities.clones'}
                )
                for f in template['fetch']:
                    if f.get('dest'):
                        source = os.path.join(CACHE_ROOT, vm['template']['name'], f['name'], f['name'])
                        source_type = self.dispatcher.call_sync('vm.datastore.get_path_type', datastore, source)
                        if cloning_supported and f['dest'] != '.' and source_type != 'FILE':
                            self.run_subtask_sync(
                                'vm.datastore.{0}.clone'.format(source_type.lower()),
                                datastore,
                                source,
                                os.path.join(files_datastore_path, f['dest'])
                            )
                        else:
                            dest = files_datastore_path if f['dest'] == '.' else os.path.join(files_datastore_path, f['dest'])
                            copytree(
                                self.dispatcher.call_sync('vm.datastore.get_filesystem_path', datastore, source),
                                self.dispatcher.call_sync('vm.datastore.get_filesystem_path', datastore, dest),
                            )

        if progress_cb:
            progress_cb(100, 'Initializing VM files')

    def regenerate_template_files(self, vm):
        template = vm.get('template')
        if not template:
            return

        vm_root = self.dispatcher.call_sync('vm.get_vm_root', vm['id'], False)

        dest_root = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', vm['target'], vm_root)

        if template.get('files'):
            source_root = os.path.join(template['path'], 'files')
            files_root = self.dispatcher.call_sync(
                'vm.datastore.get_filesystem_path',
                vm['target'],
                os.path.join(vm_root, 'files')
            )

            for root, dirs, files in os.walk(source_root):
                r = os.path.relpath(root, source_root)

                for f in files:
                    name, ext = os.path.splitext(f)
                    if ext == '.in':
                        process_template(os.path.join(root, f), os.path.join(files_root, r, name), **{
                            'VM_ROOT': dest_root
                        })
                    else:
                        shutil.copyfile(os.path.join(root, f), os.path.join(files_root, r, f))

                for d in dirs:
                    os.makedirs(os.path.join(files_root, r, d), exist_ok=True)

    def create_device(self, vm, res, progress_cb=None):
        if progress_cb:
            progress_cb(0, 'Creating {0}'.format(res['type'].lower()))

        if 'id' in vm:
            reserved_storage = self.dispatcher.call_sync('vm.get_reserved_storage', vm['id'])
            if res['type'] in ['VOLUME', 'DISK']:
                new_path = os.path.join(VM_ROOT, vm['name'], res['name'])
                if new_path in reserved_storage:
                    raise TaskException(
                        errno.EEXIST,
                        'Cannot create device {0}. Destination path {1} is already in use.'.format(
                            res['name'],
                            new_path
                        )
                    )

        if res['type'] == 'GRAPHICS':
            if q.get(vm, 'config.bootloader') != 'UEFI':
                raise TaskException(errno.EINVAL, 'Graphical consoles are supported for UEFI bootloader only.')
            normalize(res['properties'], {'resolution': '1024x768'})

        if res['type'] == 'DISK':
            vm_root_dir = get_vm_path(vm['name'])
            properties = res['properties']
            datastore = vm['target']
            normalize(properties, {
                'mode': 'AHCI',
                'target_type': 'BLOCK',
                'target_path': res['name'],
                'size': 0
            })
            if properties['target_type'] != 'DISK':
                properties['target_path'] = os.path.join(vm_root_dir, properties['target_path'])

            cloning_supported = self.dispatcher.call_sync(
                'vm.datastore.query',
                [('id', '=', datastore)],
                {'single': True, 'select': 'capabilities.clones'}
            )
            if properties.get('source'):
                source = os.path.join(CACHE_ROOT, vm['template']['name'], res['name'], res['name'])
                if cloning_supported:
                    self.run_subtask_sync(
                        'vm.datastore.block_device.clone',
                        datastore,
                        source,
                        properties['target_path']
                    )
                else:
                    copytree(
                        self.dispatcher.call_sync('vm.datastore.get_filesystem_path', datastore, source),
                        self.dispatcher.call_sync(
                            'vm.datastore.get_filesystem_path',
                            datastore,
                            properties['target_path']
                        )
                    )

            else:
                target_filesystem_path = self.dispatcher.call_sync(
                    'vm.datastore.get_filesystem_path',
                    datastore,
                    properties['target_path']
                )
                if properties['target_type'] == 'BLOCK':
                    if not os.path.exists(target_filesystem_path):
                        self.run_subtask_sync(
                            'vm.datastore.block_device.create',
                            vm['target'],
                            properties['target_path'],
                            properties['size']
                        )
                elif properties['target_type'] == 'FILE':
                    if properties['size'] or not os.path.exists(target_filesystem_path):
                        self.run_subtask_sync(
                            'vm.datastore.local.block_device.create',
                            datastore,
                            properties['target_path'],
                            properties['size']
                        )

        if res['type'] == 'NIC':
            normalize(res['properties'], {
                'device': 'VIRTIO',
                'mode': 'NAT',
                'link_address': self.dispatcher.call_sync('vm.generate_mac')
            })

            brigde = res['properties'].get('bridge', 'default')
            if brigde != 'default':
                if_exists = self.dispatcher.call_sync(
                    'network.interface.query',
                    [('or', [('id', '=', brigde), ('name', '=', brigde)])],
                    {'single': True}
                )
                if not if_exists:
                    raise TaskException(
                        errno.ENOENT,
                        'Cannot create a bridge to {0}. Interface does not exist'.format(brigde)
                    )

        if res['type'] == 'VOLUME':
            properties = res['properties']
            vm_root_dir = get_vm_path(vm['name'])
            datastore = vm['target']

            normalize(res['properties'], {
                'type': 'VT9P',
                'auto': False
            })

            if properties['type'] == 'VT9P':
                if properties.get('auto'):
                    dir_path = os.path.join(vm_root_dir, res['name'])
                    dir_exists = self.dispatcher.call_sync('vm.datastore.directory_exists', datastore, dir_path)
                    if not dir_exists and not properties.get('source'):
                        self.run_subtask_sync('vm.datastore.directory.create', datastore, dir_path)

                    if properties.get('source'):
                        cloning_supported = self.dispatcher.call_sync(
                            'vm.datastore.query',
                            [('id', '=', datastore)],
                            {'single': True, 'select': 'capabilities.clones'}
                        )
                        source = os.path.join(CACHE_ROOT, vm['template']['name'], res['name'], res['name'])
                        if dir_exists:
                            shutil.rmtree(
                                self.dispatcher.call_sync('vm.datastore.get_filesystem_path', datastore, dir_path),
                                ignore_errors=True
                            )
                        else:
                            if cloning_supported:
                                self.run_subtask_sync(
                                    'vm.datastore.directory.clone',
                                    datastore,
                                    source,
                                    dir_path
                                )
                                return
                            else:
                                self.run_subtask_sync(
                                    'vm.datastore.directory.create',
                                    datastore,
                                    dir_path
                                )

                        copytree(
                            self.dispatcher.call_sync('vm.datastore.get_filesystem_path', datastore, source),
                            self.dispatcher.call_sync('vm.datastore.get_filesystem_path', datastore, dir_path),
                        )

        res['properties'] = exclude(res['properties'], 'size', 'source')

        if progress_cb:
            progress_cb(100, 'Creating {0}'.format(res['type'].lower()))

    def update_device(self, vm, old_res, new_res):
        vm_root_dir = get_vm_path(vm['name'])
        old_properties = old_res['properties']
        new_properties = new_res['properties']

        if new_res['type'] == 'VOLUME':
            if old_res['name'] != new_res['name']:
                if old_properties['auto'] and new_properties['auto']:
                    self.run_subtask_sync('vm.datastore.directory.rename',
                        vm['target'],
                        os.path.join(vm_root_dir, old_res['name']),
                        os.path.join(vm_root_dir, new_res['name'])
                    )

            if not old_properties['auto'] and new_properties['auto']:
                self.run_subtask_sync(
                    'vm.datastore.directory.create',
                    vm['target'],
                    os.path.join(vm_root_dir, new_res['name'])
                )

            if old_properties['auto'] and not new_properties['auto']:
                new_properties['destination'] = None

        if new_res['type'] == 'DISK':
            if old_properties['target_type'] == 'BLOCK':
                if new_properties['target_type'] == 'BLOCK':
                    if old_properties['size'] != new_properties['size']:
                        self.run_subtask_sync(
                            'vm.datastore.block_device.resize',
                            vm['target'],
                            old_properties['target_path'],
                            new_properties['size']
                        )

                    if old_properties['target_path'] != new_properties['target_path']:
                        new_properties['target_path'] = os.path.join(vm_root_dir, new_properties['target_path'])
                        self.run_subtask_sync(
                            'vm.datastore.block_device.rename',
                            vm['target'],
                            old_properties['target_path'],
                            new_properties['target_path']
                        )
                elif new_properties['target_type'] == 'FILE':
                    target_filesystem_path = self.dispatcher.call_sync(
                        'vm.datastore.get_filesystem_path',
                        vm['target'],
                        new_properties['target_path']
                    )
                    if new_properties['size'] or not os.path.exists(target_filesystem_path):
                        self.run_subtask_sync(
                            'vm.datastore.local.block_device.create',
                            vm['target'],
                            new_properties['target_path'],
                            new_properties.get('size', 0)
                        )

            elif old_properties['target_type'] in ('DISK', 'FILE'):
                if new_properties['target_type'] == 'BLOCK':
                    new_properties['target_path'] = os.path.join(vm_root_dir, new_properties['target_path'])
                    target_exists = self.dispatcher.call_sync(
                        'vm.datastore.directory_exists',
                        vm['target'],
                        new_properties['target_path']
                    )
                    if not target_exists:
                        self.run_subtask_sync(
                            'vm.datastore.block_device.create',
                            vm['target'],
                            new_properties['target_path'],
                            new_properties['size']
                        )
                    else:
                        self.run_subtask_sync(
                            'vm.datastore.block_device.resize',
                            vm['target'],
                            new_properties['target_path'],
                            new_properties['size']
                        )

                elif new_properties['target_type'] == 'FILE':
                    target_filesystem_path = self.dispatcher.call_sync(
                        'vm.datastore.get_filesystem_path',
                        vm['target'],
                        new_properties['target_path']
                    )
                    if new_properties['size'] or not os.path.exists(target_filesystem_path):
                        self.run_subtask_sync(
                            'vm.datastore.local.block_device.create',
                            vm['target'],
                            new_properties['target_path'],
                            new_properties.get('size', 0)
                        )

            new_res['properties'] = exclude(new_res['properties'], 'size')

        if new_res['type'] == 'NIC':
            brigde = new_properties.get('bridge', 'default')
            if brigde != 'default':
                if_exists = self.dispatcher.call_sync(
                    'network.interface.query',
                    [('or', [('id', '=', brigde), ('name', '=', brigde)])],
                    {'single': True}
                )
                if not if_exists:
                    raise TaskException(
                        errno.ENOENT,
                        'Cannot create a bridge to {0}. Interface does not exist'.format(brigde)
                    )

    def delete_device(self, vm, res):
        reserved_storage = self.dispatcher.call_sync('vm.get_reserved_storage', vm['id'])

        if res['type'] in ('DISK', 'VOLUME'):
            path = self.dispatcher.call_sync('vm.get_device_path', vm['id'], res['name'], False)
            if path in reserved_storage:
                self.add_warning(TaskWarning(
                    errno.EACCES,
                    '{0} storage not deleted. There are VM snapshots related to {1} path.'.format(res['name'], path)
                ))
            else:
                if res['type'] == 'DISK' and q.get(res, 'properties.target_type') in ('DISK', 'FILE'):
                    return

                if res['type'] == 'VOLUME' and not q.get(res, 'properties.auto'):
                    return

                self.run_subtask_sync(
                    'vm.datastore.directory.delete',
                    vm['target'],
                    path
                )


@accepts(h.all_of(
    h.ref('Vm'),
    h.required('name', 'target')
))
@description('Creates a VM')
class VMCreateTask(VMBaseTask):
    def __init__(self, dispatcher):
        super(VMCreateTask, self).__init__(dispatcher)
        self.id = None
        self.root_dir_created = False

    @classmethod
    def early_describe(cls):
        return 'Creating VM'

    def describe(self, vm):
        return TaskDescription('Creating VM {name}', name=vm.get('name', ''))

    def verify(self, vm):
        try:
            resources = self.dispatcher.call_sync('vm.datastore.get_resources', vm['target'])
        except RpcException as err:
            raise VerifyException(err.code, 'Invalid datastore: {0}'.format(err.message))

        return resources

    def run(self, vm):
        def collect_progress(static_message, start_percentage, percentage, message=None, extra=None):
            self.set_progress(
                start_percentage + ((20 * (idx / devices_len)) + (0.2 * (percentage / devices_len))),
                '{0} {1}'.format(static_message, message),
                extra
            )

        self.set_progress(0, 'Creating VM')
        if vm.get('template'):
            template_name = vm['template'].get('name')
            template = None
            if template_name.startswith('ipfs://'):
                template = self.dispatcher.call_sync(
                    'vm.template.query',
                    [('template.hash', '=', template_name)],
                    {'single': True}
                )
                if not template:
                    self.set_progress(5, 'Fetching VM template from IPFS')
                    template_name = self.run_subtask_sync('vm.template.ipfs.fetch', template_name)

            if not template:
                template = self.dispatcher.call_sync(
                    'vm.template.query',
                    [('template.name', '=', template_name)],
                    {'single': True}
                )

            if not template:
                raise TaskException(errno.ENOENT, 'Template {0} not found'.format(vm['template'].get('name')))

            vm['template']['name'] = template['template']['name']
            template['template'].pop('readme', None)
            template['config'].pop('minmemsize', None)
            template.pop('id', None)

            result = {}
            for key in vm:
                if vm[key]:
                    result[key] = vm[key]
            deep_update(template, result)
            vm = template
            template = self.dispatcher.call_sync(
                'vm.template.query',
                [('template.name', '=', template_name)],
                {'single': True}
            )

            if vm.get('guest_type') and vm['guest_type'] != template['guest_type']:
                raise TaskException(errno.EPERM, 'Cannot change the guest type if VM is created from template')

            if vm['config'].get('bootloader') and vm['config']['bootloader'] != template['config']['bootloader']:
                raise TaskException(errno.EPERM, 'Cannot change the bootloader if VM is created from template')

            if vm['config'].get('boot_directory') and vm['config']['boot_directory'] != template['config']['boot_directory']:
                raise TaskException(errno.EPERM, 'Cannot change the boot directory if VM is created from template')

            if vm['config'].get('boot_device'):
                if vm['config']['boot_device'] != template['config']['boot_device']:
                    raise TaskException(errno.EPERM, 'Cannot change the boot device if VM is created from template')

            for device in template['devices']:
                if device['type'] == 'DISK' and q.get(device, 'properties.source'):
                    if not first_or_default(lambda o: exclude(o, 'id') == device, vm['devices']):
                        raise TaskException(errno.EPERM, 'Cannot modify disk which is defined by template')

                if device['type'] == 'GRAPHICS':
                    if not first_or_default(lambda o: o['type'] == device['type'], vm['devices']):
                        raise TaskException(
                            errno.EPERM, 'GRAPHICS device cannot be removed if the VM is created from template'
                        )

            if template['config'].get('minmemsize'):
                if vm['config']['memsize'] < template['config']['minmemsize']:
                    raise TaskException(
                        errno.EPERM,
                        'Memory cannot be set below template minimal value: {}'.format(template['config']['minmemsize'])
                    )

            self.run_subtask_sync(
                'vm.cache.update',
                vm['template']['name'],
                vm['target'],
                progress_callback=lambda p, m, e: self.chunk_progress(0, 50, '', p, m, e)
            )
        else:
            normalize(vm, {
                'config': {},
                'devices': []
            })

        normalize(vm, {
            'enabled': True,
            'immutable': False,
            'guest_type': 'other',
            'parent': None
        })

        normalize(vm['config'], {
            'memsize': 512,
            'ncpus': 1,
            'autostart': False,
            'logging': []
        })

        if vm['config']['ncpus'] < 1:
            raise TaskException(errno.EINVAL, 'VM cores value too low. Minimum permissible value is 1.')

        if vm['config']['ncpus'] > 16:
            raise TaskException(errno.EINVAL, 'Upper limit of VM cores exceeded. Maximum permissible value is 16.')

        datastore = self.dispatcher.call_sync('vm.datastore.query', [('id', '=', vm['target'])], {'single': True})
        if not datastore:
            raise TaskException(errno.EINVAL, 'Datastore {0} not found'.format(vm['target']))

        vnc_password = q.get(vm, 'config.vnc_password')
        if vnc_password:
            q.set(vm, 'config.vnc_password', vnc_password)

        self.set_progress(50, 'Initializing VM root directory')
        self.init_root_dir(vm)
        self.root_dir_created = True

        devices_len = len(vm['devices'])
        for idx, res in enumerate(vm['devices']):
            res.pop('id', None)
            self.create_device(vm, res, lambda p, m, e=None: collect_progress('Initializing VM devices:', 60, p, m, e))

        self.init_files(vm, lambda p, m, e=None: self.chunk_progress(80, 90, 'Initializing VM files:', p, m, e))

        self.id = self.datastore.insert('vms', vm)
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'create',
            'ids': [self.id]
        })

        vm = self.datastore.get_by_id('vms', self.id)
        self.set_progress(90, 'Saving VM configuration')
        save_config(
            self.dispatcher.call_sync(
                'vm.datastore.get_filesystem_path',
                vm['target'],
                get_vm_path(vm['name'])
            ),
            'vm-{0}'.format(vm['name']),
            vm,
            version=CONFIG_VERSION
        )

        if q.get(vm, 'config.autostart'):
            self.run_subtask_sync('vm.start', self.id)

        self.set_progress(100, 'Finished')

        return self.id

    def rollback(self, vm):
        vm_root_dir = get_vm_path(vm['name'])

        if self.root_dir_created and self.dispatcher.call_sync('vm.datastore.directory_exists', vm['target'], vm_root_dir):
            self.run_subtask_sync('vm.datastore.directory.delete', vm['target'], vm_root_dir)

        if self.id:
            with self.dispatcher.get_lock('vms'):
                self.dispatcher.run_hook('vm.pre_destroy', {'name': self.id})
                self.datastore.delete('vms', self.id)
                self.dispatcher.dispatch_event('vm.changed', {
                    'operation': 'delete',
                    'ids': [self.id]
                })


@accepts(str, str)
@returns(str)
@description('Imports existing VM')
class VMImportTask(VMBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Importing VM'

    def describe(self, name, datastore):
        return TaskDescription('Importing VM {name}', name=name)

    def verify(self, name, datastore):
        try:
            resources = self.dispatcher.call_sync('vm.datastore.get_resources', datastore)
        except RpcException as err:
            raise VerifyException(err.code, 'Invalid datastore: {0}'.format(err.message))

        return resources

    def run(self, name, datastore):
        if self.datastore.exists('vms', ('name', '=', name)):
            raise TaskException(errno.EEXIST, 'VM {0} already exists'.format(name))

        try:
            vm = load_config(
                self.dispatcher.call_sync(
                    'vm.datastore.get_filesystem_path',
                    datastore,
                    get_vm_path(name)
                ),
                f'vm-{name}',
                version=CONFIG_VERSION
            )
        except FileNotFoundError:
            raise TaskException(
                errno.ENOENT,
                'There is no {0} on {1} datastore to be imported.'.format(name, datastore)
            )
        except ValueError:
            raise VerifyException(
                errno.EINVAL,
                'Cannot read configuration file. File is not a valid JSON file'
            )

        vm['target'] = datastore

        id = self.datastore.insert('vms', vm)
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@private
@accepts(str, bool)
@description('Sets VM immutable')
class VMSetImmutableTask(VMBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Updating VM\'s immutable property'

    def describe(self, id, immutable):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription(
            'Setting {name} VM\'s immutable property to {value}',
            name=vm.get('name', '') if vm else '',
            value='on' if immutable else 'off'
        )

    def verify(self, id, immutable):
        return ['system']

    def run(self, id, immutable):
        if not self.datastore.exists('vms', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'VM {0} does not exist'.format(id))

        vm = self.datastore.get_by_id('vms', id)
        vm['enabled'] = not immutable
        vm['immutable'] = immutable
        self.datastore.update('vms', id, vm)
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str, h.ref('Vm'))
@description('Updates VM')
class VMUpdateTask(VMBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Updating VM'

    def describe(self, id, updated_params):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Updating VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id, updated_params):
        if 'devices' in updated_params:
            name = ""
            graphics_exist = False
            for device in updated_params['devices']:
                if device['type'] == 'GRAPHICS':
                    if graphics_exist:
                        raise VerifyException(
                            errno.EEXIST,
                            'Multiple "GRAPHICS" type devices detected: {0},{1}'.format(
                                name,
                                device['name']
                            )
                        )
                    else:
                        graphics_exist = True
                        name = device['name']

        return ['system']

    def run(self, id, updated_params):
        if not self.datastore.exists('vms', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'VM {0} not found'.format(id))

        if 'config' in updated_params and updated_params['config']['ncpus'] < 1:
            raise TaskException(errno.EINVAL, 'VM cores value too low. Minimum permissible value is 1.')

        if 'config' in updated_params and updated_params['config']['ncpus'] > 16:
            raise TaskException(errno.EINVAL, 'Upper limit of VM cores exceeded. Maximum permissible value is 16.')

        vm = self.datastore.get_by_id('vms', id)
        if vm['immutable']:
            raise TaskException(errno.EACCES, 'Cannot modify immutable VM {0}.'.format(id))

        state = self.dispatcher.call_sync('vm.query', [('id', '=', id)], {'select': 'status.state', 'single': True})
        if state != 'STOPPED':
            if 'name' in updated_params:
                raise TaskException(errno.EACCES, 'Name of a running VM cannot be modified')

            runtime_static_params = (
                'guest_type', 'enabled', 'immutable', 'target', 'template', 'devices', 'config.memsize', 'config.ncpus',
                'config.bootloader', 'config.boot_device', 'config.boot_partition', 'config.boot_directory',
                'config.cloud_init', 'config.vnc_password'
            )

            if any(q.get(updated_params, key) and q.get(vm, key) != q.get(updated_params, key) for key in runtime_static_params):
                self.add_warning(TaskWarning(
                    errno.EACCES, 'Selected change set is going to take effect after VM {0} reboot'.format(vm['name'])
                ))

        try:
            delete_config(
                self.dispatcher.call_sync(
                    'vm.datastore.get_filesystem_path',
                    vm['target'],
                    get_vm_path(vm['name'])
                ),
                'vm-{0}'.format(vm['name'])
            )
        except (RpcException, OSError):
            pass

        datastore = self.dispatcher.call_sync('vm.datastore.query', [('id', '=', vm['target'])], {'single': True})
        if not datastore:
            raise TaskException(errno.EINVAL, 'Datastore {0} not found'.format(vm['target']))

        if 'name' in updated_params:
            vm_root_dir = get_vm_path(vm['name'])
            new_vm_root_dir = get_vm_path(updated_params['name'])
            self.run_subtask_sync('vm.datastore.directory.rename', vm['target'], vm_root_dir, new_vm_root_dir)

        old_vm = self.dispatcher.call_sync('vm.query', [('id', '=', vm['id'])], {'single': True})
        vm.update(updated_params)

        if 'config' in updated_params:
            readme = updated_params['config'].pop('readme', '')
            root = self.dispatcher.call_sync('vm.get_vm_root', vm['id'])
            readme_path = get_readme(root)
            if readme_path or readme:
                with open(os.path.join(root, 'README.md'), 'w') as readme_file:
                    readme_file.write(readme)

            if q.get(vm, 'config.bootloader') != 'UEFI':
                if first_or_default(lambda i: i['type'] == 'GRAPHICS', vm['devices']):
                    raise TaskException(
                        errno.EINVAL,
                        'Cannot change bootloader type. VM has graphical console - this is only supported in UEFI mode'
                    )

            vnc_password = q.get(vm, 'config.vnc_password')
            if vnc_password:
                q.set(vm, 'config.vnc_password', vnc_password)

        if 'devices' in updated_params:
            for res in vm['devices']:
                res.pop('id', None)
                existing = first_or_default(lambda i: i['name'] == res['name'], old_vm['devices'])
                if existing:
                    self.update_device(vm, existing, res)
                else:
                    self.create_device(vm, res)

            for res in old_vm['devices']:
                if not first_or_default(lambda i: i['name'] == res['name'], updated_params['devices']):
                    self.delete_device(old_vm, res)

        if not updated_params.get('enabled', True):
            self.run_subtask_sync('vm.stop', id)

        self.datastore.update('vms', id, vm)
        if q.get(vm, 'config.bootloader') == 'GRUB':
            self.regenerate_template_files(vm)

        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'update',
            'ids': [id]
        })

        vm = self.datastore.get_by_id('vms', id)
        try:
            save_config(
                self.dispatcher.call_sync(
                    'vm.datastore.get_filesystem_path',
                    vm['target'],
                    get_vm_path(vm['name'])
                ),
                'vm-{0}'.format(vm['name']),
                vm,
                version=CONFIG_VERSION
            )
        except OSError:
            pass


@accepts(str)
@description('Deletes VM')
class VMDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting VM'

    def describe(self, id):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Deleting VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('vms', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'VM {0} not found'.format(id))

        vm = self.datastore.get_by_id('vms', id)

        clones = self.datastore.query('vms', ('parent', '=', id), select='name')
        if clones:
            raise TaskException(
                errno.EACCES,
                'Cannot delete VM {0}. VM has clones: '.format(vm['name']) + ', '.join(clones)
            )

        try:
            delete_config(
                self.dispatcher.call_sync(
                    'vm.datastore.get_filesystem_path',
                    vm['target'],
                    get_vm_path(vm['name'])
                ),
                'vm-{0}'.format(vm['name'])
            )
        except (RpcException, OSError):
            pass

        subtasks = []
        for snapshot in self.dispatcher.call_sync('vm.snapshot.query', [('parent.id', '=', id)]):
            subtasks.append(self.run_subtask('vm.snapshot.delete', snapshot['id']))
        self.join_subtasks(*subtasks)

        try:
            self.run_subtask_sync('vm.stop', id, True)
        except RpcException:
            pass

        vm_root_path = self.dispatcher.call_sync('vm.get_vm_root', id, False)
        datastore = vm['target']

        snap_sources = []
        try:
            for dir in self.dispatcher.call_sync('vm.datastore.list_dirs', datastore, vm_root_path):
                source = self.dispatcher.call_sync('vm.datastore.get_clone_source', datastore, dir)
                if source:
                    path, snap_id = source.split('@', 1)
                    if self.datastore.query('vm.snapshots', ('id', '=', snap_id)):
                        continue

                    type = 'directory'
                    if self.dispatcher.call_sync('vm.datastore.get_path_type', datastore, path) == 'BLOCK':
                        type = 'block_device'

                    snap_sources.append((type, source))

            self.run_subtask_sync('vm.datastore.directory.delete', vm['target'], get_vm_path(vm['name']))
        except RpcException as err:
            if err.code != errno.ENOENT:
                raise err

        subtasks = []
        for type, source in snap_sources:
            subtasks.append(self.run_subtask('vm.datastore.{0}.snapshot.delete'.format(type), datastore, source))

        self.join_subtasks(*subtasks)

        with self.dispatcher.get_lock('vms'):
            self.dispatcher.run_hook('vm.pre_destroy', {'name': id})
            self.datastore.delete('vms', id)
            self.dispatcher.dispatch_event('vm.changed', {
                'operation': 'delete',
                'ids': [id]
            })


@accepts(str)
@description('Exports VM from database')
class VMExportTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Exporting VM'

    def describe(self, id):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Exporting VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('vms', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'VM {0} not found'.format(id))

        self.datastore.delete('vms', id)
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@accepts(str)
@description('Starts VM')
class VMStartTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Starting VM'

    def describe(self, id):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Starting VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id):
        vm = self.datastore.get_by_id('vms', id)
        if not vm:
            raise TaskException(errno.ENOENT, f'VM {id} does not exist')

        config = vm.get('config')
        if not config or not config.get('bootloader'):
            raise VerifyException(errno.ENXIO, 'Please specify a bootloader for this vm.')
        if config['bootloader'] == 'BHYVELOAD' and not config.get('boot_device'):
            raise VerifyException(
                errno.ENXIO,
                'BHYVELOAD bootloader requires that you specify a boot device on your vm'
            )
        return ['system']

    def run(self, id):
        vm = self.dispatcher.call_sync('vm.query', [('id', '=', id)], {'single': True})
        if not vm['enabled']:
            raise TaskException(errno.EACCES, "Cannot start disabled VM {0}".format(id))

        state = q.get(vm, 'status.state')
        if state == 'ORPHANED':
            raise TaskException(errno.EACCES, 'Cannot start orphaned VM. Check datastore')

        if state != 'STOPPED':
            raise TaskException(errno.EINVAL, f'VM {vm["name"]} is already running')

        try:
            dropped_devices = self.dispatcher.call_sync('containerd.management.start_vm', id)
        except RpcException as err:
            raise TaskException(err.code, err.message)

        for d in dropped_devices:
            if d['type'] in ('DISK', 'VOLUME', 'CDROM'):
                self.add_warning(TaskWarning(
                    errno.EACCES,
                    'Cannot access storage resources of device {0}. Cannot connect device'.format(d['name'])
                ))
            else:
                self.add_warning(TaskWarning(
                    errno.EINVAL,
                    'Cannot connect device {0}. Check configuration'.format(d['name'])
                ))

        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str, bool)
@description('Stops VM')
class VMStopTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Stopping VM'

    def describe(self, id, force=False):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Stopping VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id, force=False):
        return []

    def run(self, id, force=False):
        try:
            self.dispatcher.call_sync('containerd.management.stop_vm', id, force, timeout=120)
        except RpcException as err:
            raise TaskException(err.code, err.message)

        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str, bool)
@description('Reboots VM')
class VMRebootTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Rebooting VM'

    def describe(self, id, force=False):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Rebooting VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id, force=False):
        return []

    def run(self, id, force=False):
        state = self.dispatcher.call_sync('vm.query', [('id', '=', id)], {'single': True, 'select': 'status.state'})
        if not state:
            raise TaskException(errno.ENOENT, f'VM {id} does not exist')
        elif state in ('STOPPED', 'ORPHANED'):
            raise TaskException(errno.EACCES, 'Cannot restart a stopped VM')

        try:
            self.run_subtask_sync('vm.stop', id, force)
            self.run_subtask_sync('vm.start', id)
        except RpcException as err:
            raise TaskException(err.code, err.message)


@accepts(str, str)
@returns(str)
@description('Clones a VM')
class VMCloneTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Cloning a VM'

    def describe(self, id, new_name):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription(
            'Cloning the VM {name} to {new_name}',
            name=vm.get('name', '') if vm else '',
            new_name=new_name
        )

    def verify(self, id, new_name):
        return ['system']

    def run(self, id, new_name):
        vm = self.datastore.get_by_id('vms', id)
        if not vm:
            raise TaskException(errno.ENOENT, 'VM {0} does not exist'.format(id))

        if self.datastore.exists('vms', ('name', '=', new_name)):
            raise TaskException(errno.EEXIST, 'VM {0} already exists'.format(new_name))

        state = self.dispatcher.call_sync('vm.query', [('id', '=', id)], {'select': 'status.state', 'single': True})
        if state != 'STOPPED':
            raise TaskException(errno.EACCES, 'Cannot clone a running VM')

        if q.get(vm, 'config.docker_host'):
            raise TaskException(errno.EINVAL, 'Docker hosts cannot be cloned')

        snap_cnt = self.dispatcher.call_sync(
            'vm.snapshot.query',
            [('id', '=', id)],
            {'count': True}
        )
        while True:
            snap_name = 'vm-clone-{0}-{1}'.format(new_name, snap_cnt)
            snap_exists = self.dispatcher.call_sync(
                'vm.snapshot.query',
                [('name', '=', snap_name)],
                {'count': True}
            )
            if not snap_exists:
                break

            snap_cnt += 1

        snap_id = self.run_subtask_sync('vm.snapshot.create', id, snap_name, '{0} -> {1}'.format(vm['name'], new_name))
        return self.run_subtask_sync('vm.snapshot.clone', snap_id, new_name)


class VMSnapshotBaseTask(Task):
    def run_snapshot_task(self, task, id, datastore, snapshot_id, devices, extra=None):
        subtasks = []
        disk_paths = []

        vm_root_path = self.dispatcher.call_sync('vm.get_vm_root', id, False)

        for d in devices:
            if d['type'] == 'DISK':
                disk_paths.append(self.dispatcher.call_sync('vm.get_device_path', id, d['name'], False))

        for p in self.dispatcher.call_sync('vm.datastore.list_dirs', datastore, vm_root_path):
            type = 'directory'
            if p in disk_paths:
                type = 'block_device'

            subtasks.append(self.run_subtask(
                'vm.datastore.{0}{1}.{2}'.format(type, '' if task == 'clone' else '.snapshot', task),
                datastore,
                f'{p}@{snapshot_id}',
                *(extra(p) if extra else [])
            ))

        self.join_subtasks(*subtasks)


@accepts(str)
@description('Returns VM to previously saved state')
class VMSnapshotRollbackTask(VMSnapshotBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Rollback of VM'

    def describe(self, id):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        vm_name = None
        if snapshot:
            vm_name = self.dispatcher.call_sync(
                'vm.query',
                [('id', '=', snapshot['parent'])],
                {'single': True, 'select': 'name'}
            )
        return TaskDescription('Rollback of VM {name}', name=vm_name or '')

    def verify(self, id):
        return ['system']

    def run(self, id):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        if not snapshot:
            raise TaskException(errno.ENOENT, 'Snapshot {0} does not exist'.format(id))

        vm = self.datastore.get_by_id('vms', snapshot['parent']['id'])
        if not vm:
            raise TaskException(errno.ENOENT, 'Parent VM {0} does not exist'.format(snapshot['parent']['name']))

        state = self.dispatcher.call_sync(
            'vm.query',
            [('id', '=', vm['id'])],
            {'select': 'status.state', 'single': True}
        )
        if state != 'STOPPED':
            raise TaskException(errno.EACCES, 'Cannot rollback a running VM')

        snapshot_id = snapshot['id']

        self.run_snapshot_task(
            'rollback',
            vm['id'],
            snapshot['parent']['target'],
            snapshot_id,
            snapshot['parent']['devices']
        )

        self.datastore.update('vms', snapshot['parent']['id'], snapshot['parent'])
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'update',
            'ids': [snapshot['parent']['id']]
        })


@accepts(str, str, str)
@returns(str)
@description('Creates a snapshot of VM')
class VMSnapshotCreateTask(VMSnapshotBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Creating snapshot of VM'

    def describe(self, id, name, descr):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Creating snapshot of VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id, name, descr):
        return ['system']

    def run(self, id, name, descr):
        vm = self.datastore.get_by_id('vms', id)
        if not vm:
            raise TaskException(errno.ENOENT, 'VM {0} does not exist'.format(id))

        state = self.dispatcher.call_sync('vm.query', [('id', '=', id)], {'select': 'status.state', 'single': True})
        if state != 'STOPPED':
            raise TaskException(errno.EACCES, 'Cannot create a snapshot of a running VM')

        if self.dispatcher.call_sync('vm.snapshot.query', [('name', '=', name), ('parent.id', '=', id)], {'single': True}):
            raise TaskException(errno.EEXIST, 'Snapshot {0} of VM {1} already exists'.format(name, vm['name']))

        snapshots_support = self.dispatcher.call_sync(
            'vm.datastore.query',
            [('id', '=', vm['target'])],
            {'single': True, 'select': 'capabilities.snapshots'}
        )

        if not snapshots_support:
            raise TaskException(
                errno.EINVAL,
                'Datastore {0} does not support snapshots or is unreachable'.format(vm['target'])
            )

        snapshot_id = str(uuid.uuid4())

        snapshot = {
            'id': snapshot_id,
            'name': name,
            'description': descr,
            'parent': vm
        }

        self.run_snapshot_task('create', vm['id'], vm['target'], snapshot_id, vm['devices'])

        self.datastore.insert('vm.snapshots', snapshot)
        self.dispatcher.dispatch_event('vm.snapshot.changed', {
            'operation': 'create',
            'ids': [snapshot_id]
        })

        return snapshot_id


@accepts(str, h.ref('VmSnapshot'))
@description('Updates a snapshot of VM')
class VMSnapshotUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updates snapshot of VM'

    def describe(self, id, updated_params):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        return TaskDescription('Updating VM snapshot {name}', name=snapshot.get('name') if snapshot else '')

    def verify(self, id, updated_params):
        return ['system']

    def run(self, id, updated_params):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        if not snapshot:
            raise TaskException(errno.ENOENT, 'Snapshot {0} does not exist'.format(id))

        if 'name' in updated_params:
            snapshot['name'] = updated_params['name']
        if 'description' in updated_params:
            snapshot['description'] = updated_params['description']

        self.datastore.update('vm.snapshots', id, snapshot)
        self.dispatcher.dispatch_event('vm.snapshot.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str)
@description('Deletes a snapshot of VM')
class VMSnapshotDeleteTask(VMSnapshotBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting snapshot of VM'

    def describe(self, id):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        return TaskDescription('Deleting VM snapshot {name}', name=snapshot.get('name') if snapshot else '')

    def verify(self, id):
        return ['system']

    def run(self, id):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        if not snapshot:
            raise TaskException(errno.ENOENT, 'Snapshot {0} does not exist'.format(id))

        vm_id = snapshot['parent']['id']
        datastore, reserved_storage = self.dispatcher.call_sync('vm.get_reserved_storage', vm_id)

        self.datastore.delete('vm.snapshots', id)
        self.dispatcher.dispatch_event('vm.snapshot.changed', {
            'operation': 'delete',
            'ids': [id]
        })

        if not self.dispatcher.call_sync('vm.datastore.query', [('id', '=', datastore)], {'count': True}):
            return

        devices = snapshot['parent']['devices']

        for d in list(devices):
            if d['type'] in ('DISK', 'VOLUME'):
                path = self.dispatcher.call_sync('vm.get_device_path', datastore, d['name'], False)
                snap_path = f'{path}@{id}'
                if not self.dispatcher.call_sync('vm.datastore.snapshot_exists', datastore, snap_path):
                    devices.remove(d)

        self.run_snapshot_task('delete', vm_id, snapshot['parent']['target'], id, devices)

        _, new_reserved_storage = self.dispatcher.call_sync('vm.get_reserved_storage', vm_id)
        _, dependent_storage = self.dispatcher.call_sync('vm.get_dependent_storage', vm_id)

        required_storage = list(set(new_reserved_storage + dependent_storage))

        released_storage = [d for d in reserved_storage if d not in required_storage]
        subtasks = []
        for path in released_storage:
            path_type = self.dispatcher.call_sync('vm.datastore.get_path_type', datastore, path)
            operation = 'directory' if path_type == 'DIRECTORY' else 'block_device'
            subtasks.append(self.run_subtask('vm.datastore.{0}.delete'.format(operation), datastore, path))

        self.join_subtasks(*subtasks)


@accepts(str, str, str, str, str)
@returns(str)
@description('Publishes VM snapshot over IPFS')
class VMSnapshotPublishTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Publishing VM snapshot'

    def describe(self, id, name, author, mail, descr):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        return TaskDescription('Publishing VM snapshot {name}', name=snapshot.get('name', '') if snapshot else '')

    def verify(self, id, name, author, mail, descr):
        return ['system', 'system-dataset']

    def run(self, id, name, author, mail, descr):
        ipfs_state = self.dispatcher.call_sync(
            'service.query',
            [('name', '=', 'ipfs')],
            {'single': True, 'select': 'state'}
        )
        if ipfs_state == 'STOPPED':
            raise TaskException(errno.EIO, 'IPFS service is not running. You have to start it first.')

        if self.dispatcher.call_sync('vm.template.query', [('template.name', '=', name)], {'single': True}):
            raise TaskException(errno.EEXIST, 'Template {0} already exists'.format(name))

        self.set_progress(0, 'Preparing template file')
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        if not snapshot:
            raise TaskException(errno.ENOENT, 'Snapshot {0} does not exist'.format(id))

        vm = self.datastore.get_by_id('vms', snapshot['parent']['id'])
        if not vm:
            raise TaskException(errno.ENOENT, 'Prent VM {0} does not exist'.format(snapshot['parent']['name']))

        snapshot_id = self.dispatcher.call_sync(
            'zfs.snapshot.query',
            [('properties.org\\.freenas:vm_snapshot.rawvalue', '=', id)],
            {'single': True, 'select': 'id'}
        )

        ds_name, snap_name = snapshot_id.split('@')
        publish_ds = os.path.join(ds_name, 'publish')
        cache_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_image_cache')
        templates_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_templates')

        parent = snapshot['parent']
        current_time = datetime.datetime.utcnow().isoformat().split('.')[0]
        template = {
            'template': {
                'name': name,
                'author': '{0} <{1}>'.format(author, mail),
                'description': descr,
                'created_at': {'$date': current_time},
                'updated_at': {'$date': current_time},
                'fetch': []
            },
            'config': parent['config'],
            'devices': parent['devices'],
            'type': 'VM'
        }

        self.set_progress(10, 'Preparing VM files')
        dev_cnt = len(template['devices'])

        for idx, d in enumerate(template['devices']):
            self.set_progress(10 + ((idx / dev_cnt) * 80), 'Preparing VM files: {0}'.format(d['name']))
            if (d['type'] == 'DISK') or (d['type'] == 'VOLUME' and d['properties'].get('auto')):
                source_name = d['name']
                d['properties']['source'] = source_name
                dev_snapshot = os.path.join(ds_name, source_name) + '@' + snap_name
                dest_path = os.path.join(cache_dir, name, d['name'])

                if not os.path.isdir(dest_path):
                    os.makedirs(dest_path)

                self.run_subtask_sync('zfs.clone', dev_snapshot, publish_ds)

                dest_file = None
                if d['type'] == 'DISK':
                    dest_file = os.path.join(dest_path, d['name'] + '.gz')

                    with open(os.path.join('/dev/zvol', publish_ds), 'rb') as zvol:
                        with gzip.open(dest_file, 'wb') as file:
                            for chunk in iter(lambda: zvol.read(BLOCKSIZE), b""):
                                file.write(chunk)

                elif d['type'] == 'VOLUME':
                    dest_file = os.path.join(dest_path, d['name'] + '.tar.gz')
                    self.run_subtask_sync('zfs.mount', publish_ds)
                    with tarfile.open(dest_file, 'w:gz') as tar_file:
                        tar_file.add(self.dispatcher.call_sync('volume.get_dataset_path', publish_ds))
                        tar_file.close()
                    self.run_subtask_sync('zfs.umount', publish_ds)

                if dest_file:
                    self.run_subtask_sync('zfs.destroy', publish_ds)

                    sha256_hash = sha256(dest_file, BLOCKSIZE)

                    ipfs_hashes = self.run_subtask_sync('ipfs.add', dest_path, True)
                    ipfs_hash = self.get_path_hash(ipfs_hashes, dest_path)

                    with open(os.path.join(dest_path, 'sha256'), 'w') as f:
                        f.write(sha256_hash)

                    template['template']['fetch'].append(
                        {
                            'name': d['name'],
                            'url': self.dispatcher.call_sync('ipfs.hash_to_link', ipfs_hash),
                            'sha256': sha256_hash
                        }
                    )

        self.set_progress(90, 'Publishing template')
        template_path = os.path.join(templates_dir, 'ipfs', name)
        if not os.path.isdir(template_path):
            os.makedirs(template_path)

        self.run_subtask_sync('zfs.clone', snapshot_id, publish_ds)
        self.run_subtask_sync('zfs.mount', publish_ds)
        copytree(self.dispatcher.call_sync('volume.get_dataset_path', publish_ds), template_path)
        self.run_subtask_sync('zfs.umount', publish_ds)
        self.run_subtask_sync('zfs.destroy', publish_ds)

        try:
            os.remove(os.path.join(template_path, '.config-vm-{0}.json'.format(parent['name'])))
        except FileNotFoundError:
            pass

        with open(os.path.join(template_path, 'template.json'), 'w') as f:
            f.write(dumps(template))

        ipfs_hashes = self.run_subtask_sync('ipfs.add', template_path, True)
        ipfs_link = 'ipfs://' + self.get_path_hash(ipfs_hashes, template_path)
        self.set_progress(100, 'Upload finished - template link: {0}'.format(ipfs_link))
        with open(os.path.join(template_path, 'hash'), 'w') as hash_file:
            hash_file.write(ipfs_link)

    def get_path_hash(self, ipfs_hashes, dest_path):
        for ipfs_hash in ipfs_hashes:
            if ipfs_hash['Name'] == dest_path and 'Hash' in ipfs_hash:
                return ipfs_hash['Hash']


@accepts(str, str)
@returns(str)
@description('Clones a snapshot creating a new VM')
class VMSnapshotCloneTask(VMSnapshotBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Cloning a VM snapshot'

    def describe(self, id, new_name):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)

        return TaskDescription(
            'Cloning the VM snapshot {name} to {new_name}',
            name=snapshot.get('name') or '',
            new_name=new_name or ''
        )

    def verify(self, id, new_name):
        return ['system']

    def run(self, id, new_name):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        if not snapshot:
            raise TaskException(errno.ENOENT, 'Snapshot {0} does not exist'.format(id))

        vm = self.datastore.get_by_id('vms', snapshot['parent']['id'])
        if not vm:
            raise TaskException(errno.ENOENT, 'Parent VM {0} does not exist'.format(snapshot['parent']['name']))

        if self.datastore.exists('vms', ('name', '=', new_name)):
            raise TaskException(errno.EEXIST, 'VM {0} already exists'.format(new_name))

        if q.get(vm, 'config.docker_host'):
            raise TaskException(errno.EINVAL, 'Docker hosts cannot be cloned')

        snapshot_id = snapshot['id']
        vm_name = vm['name']

        self.run_snapshot_task(
            'clone',
            vm['id'],
            snapshot['parent']['target'],
            snapshot_id,
            snapshot['parent']['devices'],
            extra=lambda p: (p.replace(vm_name, new_name, 1),)
        )

        new_vm = copy.deepcopy(snapshot['parent'])
        new_vm.pop('id', None)
        new_vm['name'] = new_name
        new_vm['parent'] = vm['id']

        parent_root = get_vm_path(q.get(snapshot, 'parent.name'))
        clone_root = get_vm_path(new_name)
        for d in new_vm['devices']:
            if d['type'] == 'NIC':
                q.set(d, 'properties.link_address', self.dispatcher.call_sync('vm.generate_mac'))
            elif d['type'] == 'DISK':
                path = q.get(d, 'properties.target_path')
                if path.startswith(parent_root):
                    path = path.replace(parent_root, clone_root)
                    q.set(d, 'properties.target_path', path)

        id = self.datastore.insert('vms', new_vm)
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@accepts(str, str)
@description('Caches VM files')
class CacheFilesTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Caching VM files'

    def describe(self, name, datastore):
        return TaskDescription('Caching VM files {name} on datastore {ds}', name=name or '', ds=datastore or '')

    def verify(self, name, datastore):
        resources = ['system']
        try:
            resources = self.dispatcher.call_sync('vm.datastore.get_resources', datastore)
        except RpcException:
            pass

        return resources

    def run(self, name, datastore):
        def collect_progress(percentage, message=None, extra=None):
            self.set_progress(
                (100 * (weight * idx)) + ((percentage * weight) / 2) + step_progress,
                'Caching files: {0}'.format(message), extra
            )

        template = self.dispatcher.call_sync(
            'vm.template.query',
            [('template.name', '=', name)],
            {'single': True}
        )
        if not template:
            raise TaskException(errno.ENOENT, 'Template of VM {0} does not exist'.format(name))

        self.set_progress(0, 'Caching images')

        if not self.dispatcher.call_sync('vm.datastore.directory_exists', datastore, CACHE_ROOT):
            # Create cache root
            self.run_subtask_sync('vm.datastore.directory.create', datastore, CACHE_ROOT)

        if not self.dispatcher.call_sync('vm.datastore.directory_exists', datastore, os.path.join(CACHE_ROOT, name)):
            # Create template root
            self.run_subtask_sync('vm.datastore.directory.create', datastore, os.path.join(CACHE_ROOT, name))

        cache_root_path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', datastore, CACHE_ROOT)

        res_cnt = len(template['template']['fetch'])
        weight = 1 / res_cnt

        for idx, res in enumerate(template['template']['fetch']):
            url = res['url']
            res_name = res['name']
            destination = os.path.join(CACHE_ROOT, name, res_name)
            sha256 = res['sha256']
            root_dir_path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', datastore, destination)

            if self.dispatcher.call_sync('vm.datastore.directory_exists', datastore, destination):
                sha256_path = os.path.join(root_dir_path, 'sha256')
                if os.path.exists(sha256_path):
                    with open(sha256_path) as sha256_file:
                        if sha256_file.read() == sha256:
                            continue

                idx = 0
                while self.dispatcher.call_sync('vm.datastore.directory_exists', datastore, f'{destination}_old{idx}'):
                    idx += 1

                self.run_subtask_sync(
                    'vm.datastore.directory.rename',
                    datastore,
                    destination,
                    f'{destination}_old{idx}'
                )

            self.run_subtask_sync('vm.datastore.directory.create', datastore, destination)

            device = first_or_default(
                lambda o: q.get(o, 'properties.source') == res_name,
                template['devices'],
                {}
            )
            size = q.get(device, 'properties.size')

            with tempfile.TemporaryDirectory(dir=cache_root_path) as download_dir:
                step_progress = 0
                self.run_subtask_sync(
                    'vm.file.download',
                    url,
                    sha256,
                    datastore,
                    download_dir,
                    progress_callback=collect_progress
                )
                step_progress = (100 * weight) / 2
                shutil.copyfile(
                    os.path.join(download_dir, 'sha256'),
                    os.path.join(root_dir_path, 'sha256')
                )
                self.run_subtask_sync(
                    'vm.file.install',
                    datastore,
                    download_dir,
                    os.path.join(destination, res_name),
                    size,
                    progress_callback=collect_progress
                )

        self.set_progress(100, 'Cached images')


@accepts(str)
@description('Deletes cached VM files')
class DeleteFilesTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting cached VM files'

    def describe(self, name):
        return TaskDescription('Deleting cached VM {name} files', name=name)

    def verify(self, name):
        return ['system']

    def run(self, name):
        template_dir = os.path.join(CACHE_ROOT, name)
        for datastore in self.dispatcher.call_sync('vm.datastore.query', [], {'select': 'id'}):
            clones = []
            if self.dispatcher.call_sync('vm.datastore.directory_exists', datastore, template_dir):
                for dir in self.dispatcher.call_sync('vm.datastore.list_dirs', datastore, template_dir):
                    for snapshot in self.dispatcher.call_sync('vm.datastore.get_snapshots', datastore, dir):
                        clones = list(self.dispatcher.call_sync(
                            'vm.datastore.get_snapshot_clones', datastore, snapshot
                        ))
                        if clones:
                            self.add_warning(TaskWarning(
                                errno.EACCES,
                                'Cannot delete template {0} cache on {1}. Template has clones'.format(name, datastore)
                            ))
                            break

                    if clones:
                        break

                if not clones:
                    self.run_subtask_sync('vm.datastore.directory.delete', datastore, template_dir)


@description('Deletes all of cached VM files')
class FlushFilesTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting VM files cache'

    def describe(self):
        return TaskDescription('Deleting VM files cache')

    def verify(self):
        return ['system']

    def run(self):
        length = self.dispatcher.call_sync('vm.template.query', [], {'count': True})
        cnt = 0
        templates = self.dispatcher.call_sync(
            'vm.template.query',
            [],
            {'select': ('template.name', 'template.cached_on')}
        )
        for name, cached in templates:
            self.set_progress((cnt / length) * 100, 'Removing unused VM template images')
            if cached:
                self.run_subtask_sync('vm.cache.delete', name)
            cnt += 1


@private
@accepts(str, str, str, str)
@description('Downloads VM file')
class DownloadFileTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Downloading VM file'

    def describe(self, url, sha256_hash, datastore, destination):
        return TaskDescription('Downloading VM file {name}', name=url or '')

    def verify(self, url, sha256_hash, datastore, destination):
        resources = ['system']
        try:
            resources = self.dispatcher.call_sync('vm.datastore.get_resources', datastore)
        except RpcException:
            pass

        return resources

    def run(self, url, sha256_hash, datastore, destination):
        done = 0

        @throttle(seconds=1)
        def progress_hook(nblocks, blocksize, totalsize):
            nonlocal done
            current_done = nblocks * blocksize
            speed = (current_done - done) / 1000
            self.set_progress((current_done / float(totalsize)) * 100, 'Downloading file {0} KB/s'.format(speed))
            done = current_done

        file_path = os.path.join(destination, url.split('/')[-1])
        sha256_path = os.path.join(destination, 'sha256')

        self.set_progress(0, 'Downloading file')
        try:
            if url.startswith('http://ipfs.io/ipfs/'):
                self.set_progress(50, 'Fetching file through IPFS')
                self.run_subtask_sync('ipfs.get', url.split('/')[-1], destination)
            else:
                try:
                    urllib.request.urlretrieve(url, file_path, progress_hook)
                except ConnectionResetError:
                    raise TaskException(errno.ECONNRESET, 'Cannot access download server to download {0}'.format(url))
        except OSError:
            raise TaskException(errno.EIO, 'URL {0} could not be downloaded'.format(url))

        if os.path.isdir(file_path):
            for f in os.listdir(file_path):
                shutil.move(os.path.join(file_path, f), destination)
            os.rmdir(file_path)
            file_path = os.path.join(destination, f)

        self.set_progress(100, 'Verifying checksum')
        if sha256(file_path, BLOCKSIZE) != sha256_hash:
            raise TaskException(errno.EINVAL, 'Invalid SHA256 checksum')

        with open(sha256_path, 'w') as sha256_file:
            sha256_file.write(sha256_hash)


@private
@accepts(str, str, str, h.one_of(int, None))
@description('Installs VM file')
class InstallFileTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Installing VM file'

    def describe(self, datastore, source, destination, size):
        return TaskDescription(
            'Installing VM file from {name} in {destination}',
            name=source or '',
            destination=destination or ''
        )

    def verify(self, datastore, source, destination, size):
        resources = ['system']
        try:
            resources = self.dispatcher.call_sync('vm.datastore.get_resources', datastore)
        except RpcException:
            pass

        return resources

    def run(self, datastore, source, destination, size):
        self.set_progress(0, 'Installing file')
        file_path = self.get_archive_path(source)

        if not file_path:
            raise TaskException(errno.ENOENT, 'Source directory {0} not found'.format(source))

        if file_path.endswith('tar.gz'):
            self.run_subtask_sync('vm.datastore.directory.create', datastore, destination)
            destination_path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', datastore, destination)
            shutil.unpack_archive(file_path, destination_path)
        else:
            if size:
                self.run_subtask_sync('vm.datastore.block_device.create', datastore, destination, size)

            destination_path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', datastore, destination)
            self.unpack_gzip(file_path, destination_path)

        self.set_progress(100, 'Finished')

    def get_archive_path(self, files_path):
        archive_path = None
        for file in os.listdir(files_path):
            if file.endswith('.gz'):
                archive_path = os.path.join(files_path, file)
        return archive_path

    def unpack_gzip(self, path, destination):
        @throttle(seconds=1)
        def report_progress():
            self.set_progress((zip_file.tell() / size) * 100, 'Installing file')

        size = os.path.getsize(path)
        with open(destination, 'wb') as dst:
            with open(path, 'rb') as zip_file:
                with gzip.open(zip_file) as src:
                    for chunk in iter(lambda: src.read(BLOCKSIZE), b""):
                        done = 0
                        total = len(chunk)

                        while done < total:
                            ret = os.write(dst.fileno(), chunk[done:])
                            if ret == 0:
                                raise TaskException(errno.ENOSPC, 'Image is too large to fit in destination')

                            done += ret
                        report_progress()


@private
@description('Downloads VM templates')
class VMTemplateFetchTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Downloading VM templates'

    def describe(self):
        return TaskDescription('Downloading VM templates')

    def verify(self):
        return ['system-dataset']

    def run(self):
        def clean_clone(url, path):
            try:
                shutil.rmtree(path)
            except shutil.Error:
                raise TaskException(errno.EACCES, 'Cannot remove templates directory: {0}'.format(path))
            except FileNotFoundError:
                pass
            try:
                pygit2.clone_repository(url, path)
            except pygit2.GitError:
                self.add_warning(TaskWarning(
                    errno.EACCES,
                    'Cannot update template cache. Result is outdated. Check networking.'
                ))
                return

        templates_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_templates')

        progress = 0
        self.set_progress(progress, 'Downloading templates')
        template_sources = self.datastore.query('vm.template_sources')
        template_sources.extend(self.dispatcher.call_sync('vm.config.get_config').get('additional_templates', []))

        if len(template_sources):
            progress_per_source = 100 / len(template_sources)
            for source in template_sources:
                if source.get('driver', '') == 'git':
                    source_path = os.path.join(templates_dir, source['id'])

                    if os.path.exists(os.path.join(source_path, '.git')):
                        try:
                            repo = pygit2.init_repository(source_path, False)

                            for remote in repo.remotes:
                                if remote.name == 'origin':
                                    remote.fetch()
                                    remote_master_id = repo.lookup_reference('refs/remotes/origin/master').target
                                    merge_result, _ = repo.merge_analysis(remote_master_id)

                                    if merge_result & pygit2.GIT_MERGE_ANALYSIS_UP_TO_DATE:
                                        continue
                                    elif merge_result & pygit2.GIT_MERGE_ANALYSIS_FASTFORWARD:
                                        repo.checkout_tree(repo.get(remote_master_id))
                                        master_ref = repo.lookup_reference('refs/heads/master')
                                        master_ref.set_target(remote_master_id)
                                        repo.head.set_target(remote_master_id)
                                    else:
                                        clean_clone(source['url'], source_path)
                        except (pygit2.GitError, KeyError):
                            self.add_warning(TaskWarning(
                                errno.EACCES,
                                'Cannot update template cache. Result is outdated. Check networking.'))
                            return
                    else:
                        clean_clone(source['url'], source_path)

                self.set_progress(progress + progress_per_source, 'Finished operation for {0}'.format(source['id']))

        self.set_progress(100, 'Templates downloaded')


@accepts(str)
@returns(str)
@description('Downloads VM template via IPFS')
class VMIPFSTemplateFetchTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Downloading VM template via IPFS'

    def describe(self, ipfs_hash):
        return TaskDescription('Downloading VM template via IPFS {name}', name=ipfs_hash)

    def verify(self, ipfs_hash):
        return ['system-dataset']

    def run(self, ipfs_hash):
        ipfs_state = self.dispatcher.call_sync(
            'service.query',
            [('name', '=', 'ipfs')],
            {'single': True, 'select': 'state'}
        )
        if ipfs_state == 'STOPPED':
            raise TaskException(errno.EIO, 'IPFS service is not running. You have to start it first.')

        templates_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_templates')
        ipfs_templates_dir = os.path.join(templates_dir, 'ipfs')
        if not os.path.isdir(ipfs_templates_dir):
            os.makedirs(ipfs_templates_dir)

        raw_hash = ipfs_hash.split('/')[-1]

        self.run_subtask_sync('ipfs.get', raw_hash, ipfs_templates_dir)

        new_template_dir = os.path.join(ipfs_templates_dir, raw_hash)
        try:
            with open(os.path.join(new_template_dir, 'template.json'), encoding='utf-8') as template_file:
                template = loads(template_file.read())
                with open(os.path.join(new_template_dir, 'hash'), 'w') as hash_file:
                    hash_file.write(ipfs_hash)
                template_name = template['template']['name']

        except OSError:
            shutil.rmtree(new_template_dir)
            raise TaskException(errno.EINVAL, '{0} is not a valid IPFS template'.format(ipfs_hash))

        shutil.move(new_template_dir, os.path.join(ipfs_templates_dir, template_name))
        return template_name


@accepts(str, str, str)
@description("Copying files between VM's or host and guest system")
class VMToolsCopyFileTask(Task):
    @classmethod
    def early_describe(cls):
        return "Copying files between VM's or host and guest system"

    def describe(self, vm_id, source_file, dest_file):
        return TaskDescription("Copying files between VM's or host and guest system")

    def verify(self, vm_id, source_file, dest_file):
        return []

    def run(self, vm_id, source_file, dest_file):
        try:
            source_type, source_file_path = source_file.split(':', maxsplit=1)
            dest_type, dest_file_path = dest_file.split(':', maxsplit=1)
        except ValueError:
            raise TaskException(errno.EINVAL, "Invalid syntax")

        if source_type =='host' and dest_type == 'guest':
            if os.path.exists(source_file_path):
                if os.stat(source_file_path).st_size > MAX_VM_TOOLS_FILE_SIZE:
                    raise TaskException(errno.EINVAL, "Provided file is too big in size")

                with open(source_file_path, 'rb') as f:
                    buffer = f.read()

                self.dispatcher.call_sync('vm.guest_put', vm_id, dest_file_path, buffer, timeout=10)

            else:
                raise TaskException(errno.EINVAL, "Provided file does not exists")

        elif source_type == 'guest' and dest_type == 'host':
            try:
                buffer = self.dispatcher.call_sync('vm.guest_get', vm_id, source_file_path, timeout=10)
            except RpcException:
                 raise TaskException(errno.EINVAL, "Provided file does not exists or it's to big in size ")

            if buffer:
                with open(dest_file_path, 'wb') as f:
                    f.write(buffer)

            else:
                raise TaskException(errno.EINVAL, "Provided file does not exists or it's to big in size ")
        
        else:
            if source_type == 'guest':
                vm_prefix = self.dispatcher.call_sync('vm.query', [('name', '=', dest_type)], {'single': True})
                if vm_prefix:
                    try:
                        buffer = self.dispatcher.call_sync('vm.guest_get', vm_id, source_file_path, timeout=10)
                    except RpcException:
                        raise TaskException(errno.EINVAL, "Provided file does not exists or it's to big in size ")

                    if buffer:
                        self.dispatcher.call_sync('vm.guest_put', vm_prefix['id'], dest_file_path, buffer, timeout=10)
                    else:
                        raise TaskException(errno.EINVAL, "Provided file does not exists or it's to big in size ")
                else:
                    raise TaskException(errno.EINVAL, "Destination host does not exists ")

            elif dest_type == 'guest':
                vm_prefix = self.dispatcher.call_sync('vm.query', [('name', '=', source_type)], {'single': True})
                if vm_prefix:
                    try:
                        buffer = self.dispatcher.call_sync('vm.guest_get', vm_prefix['id'], source_file_path, timeout=10)
                    except RpcException:
                        raise TaskException(errno.EINVAL, "Provided file does not exists or it's to big in size ")

                    if buffer:
                        self.dispatcher.call_sync('vm.guest_put', vm_id, dest_file_path, buffer, timeout=10)
                    else:
                        raise TaskException(errno.EINVAL, "Provided file does not exists or it's to big in size ")
                else:
                    raise TaskException(errno.EINVAL, "Destination host does not exists ")

            else:
                raise TaskException(errno.EINVAL, "Invalid syntax")


@accepts(str)
@description('Deletes VM template images and VM template itself')
class VMTemplateDeleteTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting VM template images and VM template'

    def describe(self, name):
        return TaskDescription('Deleting VM template images and VM template {name}', name=name)

    def verify(self, name):
        return ['system-dataset']

    def run(self, name):
        template = self.dispatcher.call_sync(
            'vm.template.query',
            [('template.name', '=', name)],
            {'single': True, 'select': 'template'}
        )
        if not template:
            raise TaskException(errno.ENOENT, 'Template {0} does not exist'.format(name))

        if template['source'] == 'github':
            raise TaskException(errno.EINVAL, 'Default templates cannot be deleted')

        template_path = template.get('path')
        if not template_path:
            raise TaskException(errno.ENOENT, 'Selected template {0} does not exist'.format(name))

        self.run_subtask_sync('vm.cache.delete', name)
        shutil.rmtree(template_path)


def get_vm_path(name):
    return os.path.join(VM_ROOT, name)


def get_readme(path):
    file_path = None
    for file in os.listdir(path):
        if file == 'README.md':
            file_path = os.path.join(path, file)

    return file_path


def convert_device_type(device):
    conversion_dict = {
        'DISK': 'directory',
        'VOLUME': 'block_device'
    }

    return conversion_dict.get(device['type'])


@throttle(minutes=10)
def fetch_templates(dispatcher):
    dispatcher.call_task_sync('vm.template.fetch')
    return True


def collect_debug(dispatcher):
    yield AttachDirectory('vm-templates', dispatcher.call_sync('system_dataset.request_directory', 'vm_templates'))
    yield AttachRPC('vm-query', 'vm.query')
    yield AttachRPC('vm-config', 'vm.config.get_config')
    yield AttachRPC('vm-templates-query', 'vm.template.query')
    yield AttachRPC('vm-snapshot-query', 'vm.snapshot.query')
    yield AttachRPC('hw-support', 'vm.get_hw_vm_capabilities')


def _depends():
    return ['VMDatastorePlugin']


def _init(dispatcher, plugin):
    global templates
    templates = EventCacheStore(dispatcher, 'vm.template')

    plugin.register_schema_definition('VmStatus', {
        'type': 'object',
        'readOnly': True,
        'properties': {
            'state': {'$ref': 'VmStatusState'},
            'health': {'$ref': 'VmStatusHealth'},
            'vm_tools_available': {'type': 'boolean'},
            'nat_lease': {'oneOf': [
                {'$ref': 'VmStatusLease'},
                {'type': 'null'}
            ]},
            'management_lease': {'oneOf': [
                {'$ref': 'VmStatusLease'},
                {'type': 'null'}
            ]}
        }
    })

    plugin.register_schema_definition('VmStatusState', {
        'type': 'string',
        'enum': ['STOPPED', 'BOOTLOADER', 'RUNNING', 'PAUSED', 'ORPHANED']
    })

    plugin.register_schema_definition('VmStatusHealth', {
        'type': 'string',
        'enum': ['HEALTHY', 'DYING', 'DEAD', 'UNKNOWN']
    })

    plugin.register_schema_definition('VmStatusLease', {
        'type': 'object',
        'properties': {
            'client_ip': {'type': 'string'},
        }
    })

    plugin.register_schema_definition('Vm', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'guest_type': {'$ref': 'VmGuestType'},
            'status': {'$ref': 'VmStatus'},
            'description': {'type': 'string'},
            'enabled': {'type': 'boolean'},
            'immutable': {'type': 'boolean'},
            'target': {'type': 'string'},
            'parent': {'type': ['string', 'null']},
            'template': {
                'type': ['object', 'null'],
                'properties': {
                    'name': {'type': 'string'},
                    'path': {'type': 'string'},
                    'source': {'type': 'string'},
                    'readme': {'type': ['string', 'null']},
                    'template_version': {'type': 'string'},
                    'cached_on': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    }
                }
            },
            'config': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'memsize': {'type': 'integer'},
                    'ncpus': {'type': 'integer'},
                    'bootloader': {'$ref': 'VmConfigBootloader'},
                    'boot_device': {'type': ['string', 'null']},
                    'boot_partition': {'type': ['string', 'null']},
                    'boot_directory': {'type': ['string', 'null']},
                    'cloud_init': {'type': ['string', 'null']},
                    'vnc_password': {'type': ['password', 'null']},
                    'autostart': {'type': 'boolean'},
                    'docker_host': {'type': 'boolean'},
                    'readme': {'type': ['string', 'null']},
                    'logging': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    }
                }
            },
            'devices': {
                'type': 'array',
                'items': {'$ref': 'VmDevice'}
            }
        }
    })

    plugin.register_schema_definition('VmSnapshot', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'description': {'type': 'string'},
            'parent': {'$ref': 'Vm'}
        }
    })

    plugin.register_schema_definition('VmConfigBootloader', {
        'type': 'string',
        'enum': ['BHYVELOAD', 'GRUB', 'UEFI', 'UEFI_CSM']
    })

    plugin.register_schema_definition('VmDevice', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'status': {'$ref': 'VmDeviceStatus'},
            'type': {'$ref': 'VmDeviceType'},
            'properties': {
                'discriminator': '%type',
                'oneOf': [
                    {'$ref': 'VmDeviceNic'},
                    {'$ref': 'VmDeviceDisk'},
                    {'$ref': 'VmDeviceCdrom'},
                    {'$ref': 'VmDeviceVolume'},
                    {'$ref': 'VmDeviceGraphics'},
                    {'$ref': 'VmDeviceUsb'},
                    {'$ref': 'VmDeviceScsi'}
                ]
            }
        },
        'required': ['name', 'type', 'properties']
    })

    plugin.register_schema_definition('VmDeviceStatus', {
        'type': 'string',
        'enum': ['CONNECTED', 'DISCONNECTED', 'ERROR', 'UNKNOWN'],
        'readOnly': True
    })

    plugin.register_schema_definition('VmDeviceType', {
        'type': 'string',
        'enum': ['DISK', 'CDROM', 'NIC', 'VOLUME', 'GRAPHICS', 'USB', 'SCSI']
    })

    plugin.register_schema_definition('VmDeviceNic', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['VmDeviceNic']},
            'device': {'$ref': 'VmDeviceNicDevice'},
            'mode': {'$ref': 'VmDeviceNicMode'},
            'link_address': {'type': 'string'},
            'bridge': {'type': ['string', 'null']}
        }
    })

    plugin.register_schema_definition('VmDeviceNicDevice', {
        'type': 'string',
        'enum': ['VIRTIO', 'E1000', 'NE2K']
    })

    plugin.register_schema_definition('VmDeviceNicMode', {
        'type': 'string',
        'enum': ['BRIDGED', 'NAT', 'HOSTONLY', 'MANAGEMENT']
    })

    plugin.register_schema_definition('VmDeviceDiskTargetType', {
        'type': 'string',
        'enum': ['BLOCK', 'FILE', 'DISK']
    })

    plugin.register_schema_definition('VmDeviceDisk', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['VmDeviceDisk']},
            'mode': {'$ref': 'VmDeviceDiskMode'},
            'size': {'type': 'integer'},
            'target_type': {'$ref': 'VmDeviceDiskTargetType'},
            'target_path': {'type': 'string'},
            'source': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('VmDeviceDiskMode', {
        'type': 'string',
        'enum': ['AHCI', 'VIRTIO']
    })

    plugin.register_schema_definition('VmDeviceCdrom', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['VmDeviceCdrom']},
            'path': {'type': 'string'}
        },
        'required': ['path']

    })

    plugin.register_schema_definition('VmDeviceVolume', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['VmDeviceVolume']},
            'type': {'$ref': 'VmDeviceVolumeType'},
            'auto': {'type': ['boolean', 'null']},
            'destination': {'type': ['string', 'null']},
            'source': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('VmDeviceVolumeType', {
        'type': 'string',
        'enum': ['VT9P']
    })

    plugin.register_schema_definition('VmDeviceGraphics', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['VmDeviceGraphics']},
            'resolution': {'$ref': 'VmDeviceGraphicsResolution'},
            'vnc_enabled': {'type': 'boolean'},
            'vnc_port': {
                'type': ['integer', 'null'],
                'minimum': 1,
                'maximum': 65535
            }
        }
    })

    plugin.register_schema_definition('VmDeviceGraphicsResolution', {
        'type': 'string',
        'enum': [
            '1920x1200',
            '1920x1080',
            '1600x1200',
            '1600x900',
            '1280x1024',
            '1280x720',
            '1024x768',
            '800x600',
            '640x480'
        ]
    })

    plugin.register_schema_definition('VmGuestType', {
        'type': 'string',
        'enum': [
            'linux64',
            'freebsd32',
            'freebsd64',
            'netbsd64',
            'openbsd32',
            'openbsd64',
            'windows64',
            'solaris64',
            'other'
        ]
    })

    plugin.register_schema_definition('VmDeviceUsb', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['VmDeviceUsb']},
            'device': {'$ref': 'VmDeviceUsbDevice'},
            'config': {
                'type': 'object'  # XXX: not sure what goes there
            }
        },
        'required': ['device']
    })

    plugin.register_schema_definition('VmDeviceUsbDevice', {
        'type': 'string',
        'enum': ['tablet']
    })

    plugin.register_schema_definition('VmDeviceScsi', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['VmDeviceScsi']},
            'port': {'type': 'integer'},
            'initiator_id': {'type': 'integer'}
        },
        'required': ['port']
    })

    plugin.register_schema_definition('VmConfig', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'network': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'management': {'type': 'string'},
                    'nat': {'type': 'string'}
                }
            },
            'additional_templates': {
                'type': 'array',
                'items': {'$ref': 'VmTemplateSource'}
            }
        }
    })

    plugin.register_schema_definition('VmTemplateSource', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'driver': {'type': 'string'},
            'url': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('VmGuestInfo', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'vm_tools_version': {'type': 'string'},
            'load_avg': {
                'type': 'array',
                'items': {'type': 'number'},
                'minItems': 3,
                'maxItems': 4
            },
            'interfaces': {'type': 'object'},
            'time': {'type': 'datetime'}
        }
    })

    plugin.register_schema_definition('VmHwCapabilites', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'vtx_enabled': {'type': 'boolean'},
            'svm_features': {'type': 'boolean'},
            'unrestricted_guest': {'type': 'boolean'}
        },
    })

    def on_snapshot_change(args):
        if args['operation'] == 'delete':
            snaps = []
            for id in args['ids']:
                path, snapid = id.split('@', 1)

                snaps.append(snapid)

            snaps = list(set(snaps))

            if snaps:
                vm_snapshots = dispatcher.call_sync('vm.snapshot.query', [('id', 'in', snaps)])
                with dispatcher.get_lock('vm_snapshots'):
                    logger.debug('Snapshots deleted. Cleaning VM snapshots {0}'.format(snaps))
                    for i in vm_snapshots:
                        dispatcher.call_task_sync('vm.snapshot.delete', i['id'])
                        logger.debug('Removed {0} VM snapshot'.format(i['name']))

    def on_datastore_change(args):
        if args['operation'] in ('delete', 'update'):
            vm_ids = dispatcher.datastore.query('vms', ('target', 'in', args['ids']), select='id')

            if vm_ids:
                dispatcher.dispatch_event('vm.changed', {
                    'operation': 'update',
                    'ids': vm_ids
                })

        if args['operation'] == 'update':
            for vm in dispatcher.call_sync('vm.query', [('target', 'in', args['ids'])]):
                if q.get(vm, 'config.autostart') and q.get(vm, 'status.state') == 'STOPPED':
                    if dispatcher.call_sync('vm.datastore.get_state', vm['target']) == 'ONLINE':
                        dispatcher.call_sync('containerd.management.retry_autostart', vm['id'])

    def init_templates(args):
        try:
            dispatcher.call_sync('vm.template.update', True)
        except RpcException:
            pass

    plugin.register_provider('vm', VMProvider)
    plugin.register_provider('vm.config', VMConfigProvider)
    plugin.register_provider('vm.snapshot', VMSnapshotProvider)
    plugin.register_provider('vm.template', VMTemplateProvider)
    plugin.register_task_handler('vm.create', VMCreateTask)
    plugin.register_task_handler('vm.import', VMImportTask)
    plugin.register_task_handler('vm.update', VMUpdateTask)
    plugin.register_task_handler('vm.delete', VMDeleteTask)
    plugin.register_task_handler('vm.export', VMExportTask)
    plugin.register_task_handler('vm.start', VMStartTask)
    plugin.register_task_handler('vm.stop', VMStopTask)
    plugin.register_task_handler('vm.reboot', VMRebootTask)
    plugin.register_task_handler('vm.clone', VMCloneTask)
    plugin.register_task_handler('vm.snapshot.create', VMSnapshotCreateTask)
    plugin.register_task_handler('vm.snapshot.update', VMSnapshotUpdateTask)
    plugin.register_task_handler('vm.snapshot.delete', VMSnapshotDeleteTask)
    plugin.register_task_handler('vm.snapshot.rollback', VMSnapshotRollbackTask)
    plugin.register_task_handler('vm.snapshot.publish', VMSnapshotPublishTask)
    plugin.register_task_handler('vm.snapshot.clone', VMSnapshotCloneTask)
    plugin.register_task_handler('vm.immutable.set', VMSetImmutableTask)
    plugin.register_task_handler('vm.file.install', InstallFileTask)
    plugin.register_task_handler('vm.file.download', DownloadFileTask)
    plugin.register_task_handler('vm.cache.update', CacheFilesTask)
    plugin.register_task_handler('vm.cache.delete', DeleteFilesTask)
    plugin.register_task_handler('vm.cache.flush', FlushFilesTask)
    plugin.register_task_handler('vm.template.fetch', VMTemplateFetchTask)
    plugin.register_task_handler('vm.template.delete', VMTemplateDeleteTask)
    plugin.register_task_handler('vm.template.ipfs.fetch', VMIPFSTemplateFetchTask)
    plugin.register_task_handler('vm.config.update', VMConfigUpdateTask)
    plugin.register_task_handler('vm.tools.copy', VMToolsCopyFileTask)

    plugin.register_hook('vm.pre_destroy')

    plugin.register_event_type('vm.changed')
    plugin.register_event_type('vm.template.changed')
    plugin.register_event_type('vm.snapshot.changed')

    plugin.register_event_handler('vm.datastore.snapshot.changed', on_snapshot_change)
    plugin.register_event_handler('vm.datastore.changed', on_datastore_change)
    dispatcher.register_event_handler_once('network.changed', init_templates)

    plugin.register_debug_hook(collect_debug)
