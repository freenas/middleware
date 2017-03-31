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

import errno
import os
import re
import gevent
import logging
import tempfile
import shutil
import base64
import copy
import bsd
import bsd.kld
import hashlib
import uuid
import itertools
from datetime import datetime
from event import sync
from cache import EventCacheStore
from lib.system import SubprocessException
from lib.freebsd import fstyp
from lib.zfs import compare_vdevs, iterate_vdevs, vdev_by_guid, split_snapshot_name, get_disks, get_disk_ids
from lib.zfs import get_resources
from task import (
    Provider, Task, ProgressTask, TaskException, TaskWarning, VerifyException, query,
    TaskDescription
)
from freenas.dispatcher.rpc import (
    RpcException, description, accepts, returns, private, SchemaHelper as h, generator
)
from utils import first_or_default, load_config, split_dataset
from datastore import DuplicateKeyException
from freenas.utils import include, exclude, normalize, chunks, yesno_to_bool, remove_unchanged, query as q
from freenas.utils.password import unpassword
from freenas.utils.copytree import count_files, copytree
from freenas.utils.lazy import lazy, unlazy
from cryptography.fernet import Fernet, InvalidToken
from freenas.dispatcher.fd import FileDescriptor
from freenas.dispatcher.jsonenc import loads, dumps
from freenas.dispatcher import Password
from debug import AttachRPC, AttachData


VOLUME_LAYOUTS = {
    'stripe': 'disk',
    'mirror': 'mirror',
    'raidz': 'raidz1',
    'raidz1': 'raidz1',
    'raidz2': 'raidz2',
    'raidz3': 'raidz3',
    'virtualization': 'mirror',
    'speed': 'mirror',
    'backup': 'raidz2',
    'safety': 'raidz2',
    'storage': 'raidz1',
    'auto': 'mirror'
}

DISKS_PER_VDEV = {
    'disk': 1,
    'mirror': 2,
    'raidz1': 3,
    'raidz2': 4,
    'raidz3': 5
}

VOLUMES_ROOT = '/mnt'
DEFAULT_ACLS = [
    {'text': 'owner@:rwxpDdaARWcCos:fd:allow'},
    {'text': 'group@:rwxpDdaARWcCos:fd:allow'},
    {'text': 'everyone@:rxaRc:fd:allow'}
]
logger = logging.getLogger('VolumePlugin')
snapshots = None
datasets = None


@description("Provides access to volumes information")
class VolumeProvider(Provider):
    @query('Volume')
    @generator
    def query(self, filter=None, params=None):
        def is_upgraded(pool):
            if q.get(pool, 'properties.version.value') != '-':
                return False

            for feat in pool['features']:
                if feat['state'] == 'DISABLED':
                    return False

            return True

        def extend(vol):
            config = self.dispatcher.call_sync('zfs.pool.query', [('id', '=', vol['id'])], {'single': True})
            encrypted = vol.get('key_encrypted', False) or vol.get('password_encrypted', False)

            if not config:
                vol['status'] = 'LOCKED' if encrypted else 'UNKNOWN'
                vol['disks'] = list(get_disk_ids(vol['topology']))
                for vdev, _ in iterate_vdevs(vol['topology']):
                    vdev['status'] = 'UNAVAIL'
            else:
                @lazy
                def collect_topology():
                    topology = config['groups']
                    for vdev, _ in iterate_vdevs(topology):
                        disk_info = self.dispatcher.call_sync(
                            'disk.query',
                            [('status.data_partition_path', '=', vdev['path']), ('online', '=', True)],
                            {'single': True, 'select': ('id', 'path')}
                        )
                        if disk_info:
                            vdev['disk_id'], vdev['path'] = disk_info

                    return topology

                vol.update({
                    'rname': 'zpool:{0}'.format(vol['id']),
                    'description': None,
                    'mountpoint': None,
                    'upgraded': None,
                    'disks': lazy(lambda: list(get_disk_ids(unlazy(collect_topology)))),
                    'topology': collect_topology,
                    'root_vdev': config['root_vdev'],
                    'status': 'LOCKED' if encrypted and config['status'] == 'UNAVAIL' else config['status'],
                    'scan': config['scan'],
                    'properties': include(
                        config['properties'],
                        'size', 'capacity', 'health', 'version', 'delegation', 'failmode',
                        'autoreplace', 'dedupratio', 'free', 'allocated', 'readonly',
                        'comment', 'expandsize', 'fragmentation', 'leaked'
                    )
                })

                if config['status'] != 'UNAVAIL':
                    vol.update({
                        'description': q.get(config, 'root_dataset.properties.org\\.freenas:description.value'),
                        'mountpoint': q.get(config, 'root_dataset.properties.mountpoint.value'),
                        'upgraded': is_upgraded(config),
                    })

            if encrypted is True:
                online = 0
                offline = 0
                for vdev, _ in get_disks(unlazy(vol['topology'])):
                    try:
                        vdev_conf = self.dispatcher.call_sync('disk.get_disk_config', vdev)
                        if vdev_conf.get('encrypted', False) is True:
                            online += 1
                        else:
                            offline += 1
                    except RpcException:
                        offline += 1
                        pass

                if offline == 0:
                    presence = 'ALL'
                elif online == 0:
                    presence = 'NONE'
                else:
                    presence = 'PART'
            else:
                presence = None

            vol.update({
                'providers_presence': presence
            })

            return vol

        return q.query(
            self.datastore.query_stream('volumes', callback=extend),
            *(filter or []),
            stream=True,
            **(params or {})
        )

    @description("Finds volumes available for import")
    @accepts()
    @returns(h.array(
        h.object(properties={
            'id': str,
            'name': str,
            'topology': h.ref('ZfsTopology'),
            'disks': h.array(str),
            'status': str
        })
    ))
    def find(self):
        result = []
        for pool in self.dispatcher.call_sync('zfs.pool.find'):
            topology = pool['groups']
            for vdev, _ in iterate_vdevs(topology):
                try:
                    vdev['path'] = self.dispatcher.call_sync(
                        'disk.partition_to_disk',
                        vdev['path']
                    )

                    vdev['disk_id'] = self.dispatcher.call_sync(
                        'disk.path_to_id',
                        vdev['path']
                    )
                except RpcException:
                    pass

            if self.datastore.exists('volumes', ('id', '=', pool['guid'])):
                continue

            result.append({
                'id': str(pool['guid']),
                'name': pool['name'],
                'topology': topology,
                'disks': list(get_disk_ids(topology)),
                'status': pool['status']
            })

        return result

    @returns(h.array(h.ref('ImportableDisk')))
    def find_media(self):
        result = []

        for disk in self.dispatcher.call_sync('disk.query', [('path', 'in', self.get_available_disks())]):
            # Try whole disk first
            typ, label = fstyp(disk['path'])
            if typ:
                result.append({
                    'path': disk['path'],
                    'size': disk['mediasize'],
                    'fstype': typ,
                    'label': label or disk['status'].get('description')
                })

            for part in q.get(disk, 'status.partitions'):
                path = part['paths'][0]
                typ, label = fstyp(path)
                if typ:
                    result.append({
                        'path': path,
                        'size': part['mediasize'],
                        'fstype': typ,
                        'label': label or part['label']
                    })

        return result

    @accepts(str, str)
    @returns(str)
    def resolve_path(self, volname, path):
        mountpoint = self.dispatcher.call_sync(
            'volume.query',
            [('id', '=', volname)],
            {'single': True, 'select': 'mountpoint'}
        )

        if not mountpoint:
            raise RpcException(errno.ENOENT, f'Volume {volname} not found or not mounted')

        if self.dispatcher.call_sync(
            'volume.dataset.query',
            [('id', '=', os.path.join(volname, path)), ('type', '=', 'VOLUME')],
            {'single': True, 'select': 'id'}
        ):
            return os.path.join('/dev/zvol', volname, path)

        return os.path.join(mountpoint, path)

    @accepts(str)
    @returns(str)
    def get_dataset_path(self, dsname):
        return os.path.join(VOLUMES_ROOT, dsname)

    @description("Extracts volume name, dataset name and relative path from full path")
    @accepts(str)
    @returns(h.tuple(str, str, h.one_of(str, None)))
    def decode_path(self, path):
        path = os.path.normpath(path)[1:]
        tokens = path.split(os.sep)

        if tokens[0:2] == ['dev', 'zvol']:
            return tokens[2], '/'.join(tokens[2:]), None

        if tokens[0] != VOLUMES_ROOT[1:] or len(tokens) == 1:
            raise RpcException(errno.EINVAL, 'Invalid path')

        volname = tokens[1]
        vol = self.dispatcher.call_sync('volume.query', [('id', '=', volname)], {'single': True})
        if not vol:
            raise RpcException(errno.ENOENT, "Volume '{0}' does not exist".format(volname))

        datasets = list(self.dispatcher.call_sync('volume.dataset.query', [('volume', '=', volname)], {'select': 'id'}))
        n = len(tokens)

        while n > 0:
            fragment = '/'.join(tokens[1:n])
            if fragment in datasets:
                return volname, fragment, '/'.join(tokens[n:])

            n -= 1

        raise RpcException(errno.ENOENT, 'Cannot look up path')

    @description("Returns Disks associated with Volume specified in the call")
    @accepts(str)
    @returns(h.array(str))
    def get_volume_disks(self, name):
        result = []
        vol = self.dispatcher.call_sync('volume.query', [('id', '=', name)], {'single': True})
        if not vol:
            raise RpcException(errno.ENOENT, f'Volume {name} not found')

        encrypted = vol.get('key_encrypted', False) or vol.get('password_encrypted', False)
        if not encrypted or vol.get('providers_presence', 'NONE') != 'NONE':
            for dev in self.dispatcher.call_sync('zfs.pool.get_disks', name):
                try:
                    result.append(self.dispatcher.call_sync('disk.partition_to_disk', dev))
                except RpcException:
                    pass

        return result

    @description("Returns dataset tree for given pool")
    @accepts(str)
    @returns(h.ref('ZfsDataset'))
    def get_dataset_tree(self, name):
        pool = self.dispatcher.call_sync(
            'zfs.pool.query',
            [('name', '=', name)],
            {"single": True})

        if not pool:
            return None

        return pool['root_dataset']

    @description("Returns the list of disks currently not used by any Volume")
    @accepts()
    @returns(h.array(str))
    def get_available_disks(self):
        disks = set(self.dispatcher.call_sync('disk.query', [('online', '=', True)], {'select': 'id'}))
        for pool in self.dispatcher.call_sync('zfs.pool.query'):
            for dev in self.dispatcher.call_sync('zfs.pool.get_disks', pool['id']):
                try:
                    disk = self.dispatcher.call_sync('disk.partition_to_disk', dev)
                except RpcException:
                    continue

                if disk in disks:
                    disks.remove(disk)

        return list(disks)

    @description("Returns allocation of given disk")
    @accepts(h.array(str))
    @returns(h.ref('DisksAllocation'))
    def get_disks_allocation(self, disks):
        ret = {}
        boot_pool = self.dispatcher.call_sync('boot.pool.get_config')

        for dev in boot_pool['disks']:
            ret[dev['disk_id']] = {'type': 'BOOT'}

        for vol in self.dispatcher.call_sync('volume.query'):
            if vol['status'] in ('UNAVAIL', 'UNKNOWN'):
                continue

            for dev in vol['disks']:
                if dev in disks:
                    ret[dev] = {
                        'type': 'VOLUME',
                        'name': vol['id']
                    }

        disks = self.dispatcher.call_sync(
            'disk.query',
            [('id', 'in', list(set(disks) - set(ret.keys()))), ('online', '=', True)]
        )

        for disk in disks:
            try:
                label = self.get_disk_label(disk['path'])
                ret[disk['id']] = {
                    'type': 'EXPORTED_VOLUME',
                    'name': label['volume_id']
                }
            except RpcException:
                continue

        return ret

    @accepts(str, str)
    @returns(h.ref('ZfsVdev'))
    def vdev_by_guid(self, volume, guid):
        vdev = self.dispatcher.call_sync('zfs.pool.vdev_by_guid', volume, guid)
        if vdev:
            vdev['path'] = self.dispatcher.call_sync(
                'disk.partition_to_disk',
                vdev['path']
            )

        return vdev

    @accepts(str)
    @returns(h.ref('VolumeDiskLabel'))
    def get_disk_label(self, disk):
        label = None

        try:
            dev = get_disk_gptid(self.dispatcher, disk)
            if dev:
                label = self.dispatcher.call_sync('zfs.pool.get_disk_label', dev)
        except:
            pass

        if not label:
            try:
                label = self.dispatcher.call_sync('zfs.pool.get_disk_label', disk)
            except:
                pass

        if not label:
            raise RpcException(errno.ENOENT, 'Label not found')

        try:
            return {
                'volume_id': label['name'],
                'volume_guid': str(label['pool_guid']),
                'vdev_guid': str(label['guid']),
                'hostname': label['hostname'],
                'hostid': label.get('hostid')
            }
        except KeyError:
            raise RpcException(errno.EINVAL, 'Invalid label')

    @description("Returns volume capabilities")
    @accepts(str)
    @returns(h.object())
    def get_capabilities(self, type):
        if type == 'zfs':
            return self.dispatcher.call_sync('zfs.pool.get_capabilities')

        raise RpcException(errno.EINVAL, 'Invalid volume type')

    @accepts()
    @returns(str)
    @private
    def get_volumes_root(self):
        return VOLUMES_ROOT

    @accepts()
    @returns(h.ref('VolumeVdevRecommendations'))
    def vdev_recommendations(self):
        return {
            "storage": {
                "storage": {"drives": 9, "type": "raidz1"},
                "redundancy": {"drives": 10, "type": "raidz2"},
                "speed": {"drives": 7, "type": "raidz1"}
            },
            "redundancy": {
                "storage": {"drives": 8, "type": "raidz2"},
                "redundancy": {"drives": 4, "type": "raidz2"},
                "speed": {"drives": 6, "type": "raidz1"}
            },
            "speed": {
                "storage": {"drives": 3, "type": "raidz1"},
                "redundancy": {"drives": 2, "type": "mirror"},
                "speed": {"drives": 2, "type": "mirror"}
            }
        }


@description('Provides information about datasets')
class DatasetProvider(Provider):
    @query('VolumeDataset')
    @generator
    def query(self, filter=None, params=None):
        return datasets.query(*(filter or []), stream=True, **(params or {}))


@description('Provides information about snapshots')
class SnapshotProvider(Provider):
    @query('VolumeSnapshot')
    @generator
    def query(self, filter=None, params=None):
        return snapshots.query(*(filter or []), stream=True, **(params or {}))

    @accepts(str, str)
    @returns(str)
    def get_snapshot_name(self, dataset, prefix=None):
        if not prefix:
            prefix = 'auto'

        snapname = '{0}-{1:%Y%m%d.%H%M}'.format(prefix, datetime.utcnow())
        base_snapname = snapname

        # Pick another name in case snapshot already exists
        for i in range(1, 99):
            if self.dispatcher.call_sync(
                'zfs.snapshot.query',
                [('name', '=', '{0}@{1}'.format(dataset, snapname))],
                {'count': True}
            ):
                snapname = '{0}-{1}'.format(base_snapname, i)
                continue

            break

        return snapname


@description("Creating a volume")
@accepts(
    h.all_of(
        h.ref('Volume'),
        h.required('id', 'topology')
    ),
    h.one_of(Password, None),
    h.one_of(h.ref('VolumeDatasetProperties'), None),
)
class VolumeCreateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Creating a volume"

    def describe(self, volume, password=None, dataset_properties=None):
        return TaskDescription("Creating volume {name}", name=volume['id'])

    def verify(self, volume, password=None, dataset_properties=None):
        missing = []
        resources = []
        for i, _ in get_disks(volume['topology']):
            disk_id = disk_spec_to_id(self.dispatcher, i)
            if not disk_id:
                missing.append(i)
                continue

            resources.append(f'disk:{disk_id}')

        if volume.get('type', 'zfs') != 'zfs':
            raise TaskException(errno.EINVAL, 'Invalid volume type')

        if missing:
            raise VerifyException(errno.ENOENT, f'Following disks were not found: {", ".join(missing)}')

        return resources

    def run(self, volume, password=None, dataset_properties=None):
        if self.datastore.exists('volumes', ('id', '=', volume['id'])):
            raise TaskException(errno.EEXIST, 'Volume with same name already exists')

        key = None
        salt = None
        digest = None
        fsopts = dataset_properties or {}
        name = volume['id']
        type = volume.get('type', 'zfs')
        params = volume.get('params') or {}
        mount = params.get('mount', True)
        key_encryption = volume.pop('key_encrypted', False)
        password_encryption = volume.pop('password_encrypted', False)
        auto_unlock = volume.pop('auto_unlock', None)
        mountpoint = params.pop('mountpoint', os.path.join(VOLUMES_ROOT, volume['id']))
        available_disks = self.dispatcher.call_sync('volume.get_available_disks')
        swapsize = self.configstore.get('system.swapondrive') * 1024

        if auto_unlock and (not key_encryption or password_encryption):
            raise TaskException(
                errno.EINVAL,
                'Automatic volume unlock can be selected for volumes using only key based encryption.'
            )

        self.dispatcher.run_hook('volume.pre_create', {'name': name})
        if key_encryption:
            key = base64.b64encode(os.urandom(256)).decode('utf-8')

        if password_encryption:
            if not password:
                raise TaskException(errno.EINVAL, 'Please provide a password when choosing a password based encryption')
            salt, digest = get_digest(password)

        self.set_progress(10)

        subtasks = []
        for dname, dgroup in get_disks(volume['topology']):
            disk_id = self.dispatcher.call_sync('disk.path_to_id', dname)
            if disk_id not in available_disks:
                raise TaskException(errno.EBUSY, f'Disk {dname} is not available to use')

            if self.dispatcher.call_sync('disk.is_geli_provider', disk_id):
                self.run_subtask_sync('disk.geli.kill', disk_id)

            subtasks.append(self.run_subtask('disk.format.gpt', disk_id, 'freebsd-zfs', {
                'blocksize': params.get('blocksize', 4096),
                'swapsize': params.get('swapsize', swapsize) if dgroup == 'data' else 0
            }))

        self.join_subtasks(*subtasks)

        disk_ids = []
        for dname, dgroup in get_disks(volume['topology']):
            disk_ids.append(self.dispatcher.call_sync('disk.path_to_id', dname))

        self.set_progress(20)

        if key_encryption or password_encryption:
            subtasks = []
            for disk_id in disk_ids:
                subtasks.append(self.run_subtask('disk.geli.init', disk_id, {
                    'key': key,
                    'password': password
                }))
            self.join_subtasks(*subtasks)
            self.set_progress(30)

            subtasks = []
            for disk_id in disk_ids:
                subtasks.append(self.run_subtask('disk.geli.attach', disk_id, {
                    'key': key,
                    'password': password
                }))
            self.join_subtasks(*subtasks)

        self.set_progress(40)

        with self.dispatcher.get_lock('volumes'):
            self.run_subtask_sync(
                'zfs.pool.create',
                name,
                convert_topology_to_gptids(
                    self.dispatcher,
                    volume['topology']
                ),
                {
                    'mountpoint': mountpoint,
                    'fsopts': fsopts
                }
            )

            self.run_subtask_sync(
                'zfs.update',
                name,
                {'org.freenas:permissions_type': {'value': 'PERM'}}
            )

            self.set_progress(60)

            if mount:
                self.run_subtask_sync('zfs.mount', name)

            self.set_progress(80)

            for vdev, _ in iterate_vdevs(volume['topology']):
                vdev['disk_id'] = self.dispatcher.call_sync(
                    'disk.query',
                    [('path', '=', vdev['path']), ('online', '=', True)],
                    {'single': True, 'select': 'id'}
                )

            pool = self.dispatcher.call_sync('zfs.pool.query', [('name', '=', name)], {'single': True})
            self.datastore.insert('volumes', {
                'id': name,
                'guid': str(pool['guid']),
                'type': type,
                'mountpoint': mountpoint,
                'topology': volume['topology'],
                'encryption': {
                    'key': key,
                    'hashed_password': digest,
                    'salt': salt,
                    'slot': 0 if key_encryption or password_encryption else None},
                'key_encrypted': key_encryption,
                'password_encrypted': password_encryption,
                'auto_unlock': auto_unlock,
                'attributes': volume.get('attributes', {})
            })

        self.set_progress(90)
        wait_for_cache(self.dispatcher, 'volume', 'create', name)
        return name


@description("Creates new volume and automatically guesses disks layout")
@accepts(str, str, str, h.array(str), h.array(str), h.array(str), h.one_of(bool, None), h.one_of(Password, None), h.one_of(bool, None))
class VolumeAutoCreateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Creating a volume"

    def describe(self, name, type, layout, disks, cache_disks=None, log_disks=None, key_encryption=False, password=None, auto_unlock=None):
        return TaskDescription("Creating the volume {name}", name=name)

    def verify(self, name, type, layout, disks, cache_disks=None, log_disks=None, key_encryption=False, password=None, auto_unlock=None):
        if not disks:
            raise VerifyException('No disks provided')

        if disks == ['auto']:
            return ['disk:{0}'.format(disk) for disk in self.dispatcher.call_sync('disk.query', {'select': 'id'})]
        else:
            missing = []
            resources = []
            for i in itertools.chain(disks, cache_disks or [], log_disks or []):
                disk_id = disk_spec_to_id(self.dispatcher, i)
                if not disk_id:
                    missing.append(i)
                    continue

                resources.append(f'disk:{disk_id}')

            if missing:
                raise VerifyException(errno.ENOENT, f'Following disks were not found: {", ".join(missing)}')

            return resources

    def run(self, name, type, layout, disks, cache_disks=None, log_disks=None, key_encryption=False, password=None, auto_unlock=None):
        if self.datastore.exists('volumes', ('id', '=', name)):
            raise TaskException(
                errno.EEXIST,
                'Volume with same name already exists'
            )

        vdevs = []
        ltype = VOLUME_LAYOUTS[layout]
        ndisks = DISKS_PER_VDEV[ltype]

        if disks == ['auto']:
            available_disks = self.dispatcher.call_sync(
                'disk.query',
                [('id', 'in', self.dispatcher.call_sync('volume.get_available_disks'))]
            )

            if not available_disks:
                raise TaskException(errno.EBUSY, 'No free disks found')

            available_disks = sorted(
                available_disks,
                key=lambda item: (not item['status']['is_ssd'], item['mediasize'], item['status']['max_rotation']),
                reverse=True
            )

            disks = q.query(
                available_disks,
                ('status.is_ssd', '=', available_disks[0]['status']['is_ssd']),
                ('status.max_rotation', '=', available_disks[0]['status']['max_rotation']),
                ('mediasize', '=', available_disks[0]['mediasize']),
                select='path'
            )

        if len(disks) == 1:
            ltype = 'disk'
            ndisks = 1

        for chunk in chunks(disks, ndisks):
            if len(chunk) != ndisks:
                break

            if ltype == 'disk':
                vdevs.append({
                    'type': 'disk',
                    'path': disk_spec_to_path(self.dispatcher, chunk[0])
                })
            else:
                vdevs.append({
                    'type': ltype,
                    'children': [
                        {'type': 'disk', 'path': disk_spec_to_path(self.dispatcher, i)} for i in chunk
                    ]
                })

        cache_vdevs = [
            {'type': 'disk', 'path': disk_spec_to_path(self.dispatcher, i)} for i in cache_disks or []
        ]

        log_vdevs = [
            {'type': 'disk', 'path': disk_spec_to_path(self.dispatcher, i)} for i in log_disks or []
        ]

        id = self.run_subtask_sync(
            'volume.create',
            {
                'id': name,
                'type': type,
                'topology': {
                    'data': vdevs,
                    'cache': cache_vdevs,
                    'log': log_vdevs
                },
                'key_encrypted': key_encryption,
                'password_encrypted': True if password else False,
                'auto_unlock': auto_unlock
            },
            password,
            progress_callback=lambda p, m, e=None: self.chunk_progress(
                0, 100, '', p, m, e
            )
        )

        return id


@description("Destroys active volume")
@accepts(str)
class VolumeDestroyTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting volume"

    def describe(self, id):
        return TaskDescription("Deleting the volume {name}", name=id)

    def verify(self, id):
        return ['volume:{0}'.format(id)]

    def run(self, id):
        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})
        if not vol:
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        config = self.dispatcher.call_sync('zfs.pool.query', [('id', '=', id)], {'single': True})

        self.dispatcher.run_hook('volume.pre_destroy', {'name': id})

        with self.dispatcher.get_lock('volumes'):
            if config:
                try:
                    self.run_subtask_sync('zfs.umount', id)
                except RpcException as err:
                    pass

                try:
                    action = 'export' if vol['status'] in ('UNAVAIL', 'LOCKED') else 'destroy'
                    self.run_subtask_sync('zfs.pool.{0}'.format(action), id)
                except RpcException as err:
                    if err.code == errno.EBUSY:
                        # Find out what's holding unmount or destroy
                        files = list(itertools.chain(
                            self.dispatcher.call_sync('filesystem.get_open_files', vol['mountpoint']),
                            self.dispatcher.call_sync('filesystem.get_open_files', os.path.join('/dev/zvol', vol['id'])),
                        ))

                        if len(files) == 1:
                            raise TaskException(
                                errno.EBUSY,
                                'Volume is in use by {process_name} (pid {pid}, path {path})'.format(**files[0]),
                                extra=files
                            )
                        else:
                            raise TaskException(
                                errno.EBUSY,
                                'Volume is in use by {0} processes'.format(len(files)),
                                extra=files
                            )
                    else:
                        raise

            try:
                if vol.get('mountpoint'):
                    os.rmdir(vol['mountpoint'])
            except FileNotFoundError:
                pass

            volume_encrypted = vol.get('key_encrypted') or vol.get('password_encrypted')
            subtasks = []
            if 'topology' in vol:
                for dname, _ in get_disks(vol['topology']):
                    disk_id = self.dispatcher.call_sync('disk.path_to_id', dname)
                    disk_encrypted = self.dispatcher.call_sync(
                        'disk.query',
                        [('id', '=', disk_id)],
                        {'single': True, 'select': 'status.encrypted'}
                    )
                    if (disk_encrypted or volume_encrypted) and disk_id:
                        subtasks.append(self.run_subtask('disk.geli.kill', disk_id))
                self.join_subtasks(*subtasks)

            self.datastore.delete('volumes', vol['id'])
            self.dispatcher.dispatch_event('volume.changed', {
                'operation': 'delete',
                'ids': [vol['id']]
            })


@accepts(str)
class ExportedVolumeDestroyTask(Task):
    @classmethod
    def early_describe(cls):
        return "Destroying an exported volume"

    def describe(self, id):
        return TaskDescription("Destroying an exported volume {name}", name=id)

    def verify(self, id):
        disks = self.dispatcher.call_sync('disk.query', {'select': 'id'})
        return ['disk:{0}'.format(d) for d in disks]

    def run(self, id):
        self.run_subtask_sync('zfs.pool.destroy_exported', id)


@description("Updates configuration of existing volume")
@accepts(str, h.ref('Volume'), h.one_of(Password, None))
class VolumeUpdateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Updating a volume"

    def describe(self, id, updated_params, password=None):
        return TaskDescription("Updating the volume {name}", name=id)

    def verify(self, id, updated_params, password=None):
        vol = self.datastore.get_by_id('volumes', id)
        if not vol:
            raise VerifyException(errno.ENOENT, 'Volume {0} not found'.format(id))

        topology = updated_params.get('topology')
        if not topology:
            disks = self.dispatcher.call_sync('volume.get_volume_disks', id)
            return ['disk:{0}'.format(d) for d in disks]

        return get_resources(topology)

    def run(self, id, updated_params, password=None):
        if password is None:
            password = Password('')

        volume = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})
        available_disks = self.dispatcher.call_sync('volume.get_available_disks')
        remove_unchanged(updated_params, volume)

        encryption = volume.get('encryption')
        if not volume:
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        if 'id' in updated_params:
            # Renaming pool. Need to export and import again using different name
            new_name = updated_params['id']
            self.dispatcher.run_hook('volume.pre_rename', {'name': id, 'new_name': new_name})

            # Rename mountpoint
            self.run_subtask_sync('zfs.update', id, {
                'mountpoint': {'value': '{0}/{1}'.format(VOLUMES_ROOT, new_name)}
            })

            self.run_subtask_sync('zfs.pool.export', id)
            self.run_subtask_sync('zfs.pool.import', volume['guid'], new_name)

            # Configure newly imported volume
            self.run_subtask_sync('zfs.update', new_name, {})
            self.run_subtask_sync('zfs.mount', new_name)

            volume['id'] = new_name
            self.datastore.update('volumes', volume['id'], volume)
            self.dispatcher.run_hook('volume.post_rename', {
                'name': id,
                'mountpoint': os.path.join(VOLUMES_ROOT, id),
                'new_name': new_name,
                'new_mountpoint': os.path.join(VOLUMES_ROOT, new_name)
            })

        if 'topology' in updated_params:
            new_vdevs = {}
            removed_vdevs = []
            updated_vdevs = []
            params = {}
            subtasks = []
            swapsize = self.configstore.get('system.swapondrive') * 1024
            new_topology = updated_params['topology']
            old_topology = self.dispatcher.call_sync(
                'volume.query',
                [('id', '=', id)],
                {'single': True, 'select': 'topology'}
            )

            for group, vdevs in old_topology.items():
                for vdev in vdevs:
                    new_vdev = first_or_default(lambda v: v.get('guid') == vdev['guid'], new_topology.get(group, []))
                    if not new_vdev:
                        # Vdev is missing - it's either remove vdev request or bogus topology
                        if group == 'data':
                            raise TaskException(errno.EBUSY, 'Cannot remove data vdev {0}'.format(vdev['guid']))

                        removed_vdevs.append(vdev['guid'])
                        continue

                    if compare_vdevs(new_vdev, vdev):
                        continue

                    if new_vdev['type'] not in ('disk', 'mirror'):
                        raise TaskException(
                            errno.EINVAL,
                            'Cannot detach vdev {0}, {1} is not mirror or disk'.format(
                                vdev['guid'],
                                vdev['type']
                            )
                        )

                    if vdev['type'] not in ('disk', 'mirror'):
                        raise TaskException(
                            errno.EINVAL,
                            'Cannot change vdev {0} type ({1}) to {2}'.format(
                                vdev['guid'],
                                vdev['type'],
                                new_vdev['type']
                            )
                        )

                    if vdev['type'] == 'mirror' and new_vdev['type'] == 'mirror' and len(new_vdev['children']) < 2:
                        raise TaskException(
                            errno.EINVAL,
                            'Cannot mirror vdev {0} must have at least two members'.format(vdev['guid'])
                        )

                    if new_vdev['type'] == 'mirror':
                        for i in vdev['children']:
                            if not first_or_default(lambda v: v.get('guid') == i['guid'], new_vdev['children']):
                                removed_vdevs.append(i['guid'])

            for group, vdevs in list(updated_params['topology'].items()):
                for vdev in vdevs:
                    if 'guid' not in vdev:
                        if encryption['hashed_password'] is not None:
                            if not is_password(
                                password,
                                encryption.get('salt', ''),
                                encryption.get('hashed_password', '')
                            ):
                                raise TaskException(
                                    errno.EINVAL,
                                    'Password provided for volume {0} configuration update is not valid'.format(id)
                                )
                        new_vdevs.setdefault(group, []).append(vdev)
                        continue

                    # look for vdev in existing configuration using guid
                    old_vdev = first_or_default(lambda v: v['guid'] == vdev['guid'], old_topology[group])
                    if not old_vdev:
                        raise TaskException(errno.EINVAL, 'Cannot extend vdev {0}: not found'.format(vdev['guid']))

                    if compare_vdevs(old_vdev, vdev):
                        continue

                    if old_vdev['type'] not in ('disk', 'mirror'):
                        raise TaskException(
                            errno.EINVAL,
                            'Cannot extend vdev {0}, {1} is not mirror or disk'.format(
                                old_vdev['guid'],
                                old_vdev['type']
                            )
                        )

                    if vdev['type'] != 'mirror':
                        raise TaskException(
                            errno.EINVAL,
                            'Cannot change vdev {0} type ({1}) to {2}'.format(
                                old_vdev['guid'],
                                old_vdev['type'],
                                vdev['type']
                            )
                        )

                    if old_vdev['type'] == 'mirror' and vdev['type'] == 'mirror' and \
                       len(old_vdev['children']) + 1 != len(vdev['children']):
                        raise TaskException(
                            errno.EINVAL,
                            'Cannot extend mirror vdev by more than one disk at once'.format(vdev['guid'])
                        )

                    if old_vdev['type'] == 'disk' and vdev['type'] == 'mirror' and len(vdev['children']) != 2:
                        raise TaskException(
                            errno.EINVAL,
                            'Cannot extend disk vdev by more than one disk at once'.format(vdev['guid'])
                        )

                    updated_vdevs.append({
                        'target_guid': vdev['guid'],
                        'vdev': vdev['children'][-1]
                    })

            for vdev in removed_vdevs:
                self.run_subtask_sync('zfs.pool.detach', id, vdev)

            for vdev, group in iterate_vdevs(new_vdevs):
                disk_id = self.dispatcher.call_sync('disk.path_to_id', vdev['path'])
                if not disk_id:
                    raise TaskException(errno.ENOENT, f'Disk {vdev["path"]} not found')

                if disk_id not in available_disks:
                    raise TaskException(errno.EBUSY, f'Disk {vdev["path"]} is not available to use')

                if vdev['type'] == 'disk':
                    subtasks.append(self.run_subtask(
                        'disk.format.gpt',
                        disk_id,
                        'freebsd-zfs',
                        {
                            'blocksize': params.get('blocksize', 4096),
                            'swapsize': params.get('swapsize', swapsize) if group == 'data' else 0
                        }
                    ))

            for vdev in updated_vdevs:
                disk_id = self.dispatcher.call_sync('disk.path_to_id', vdev['vdev']['path'])
                if not disk_id:
                    raise TaskException(errno.ENOENT, f'Disk {vdev["vdev"]["path"]} not found')

                if disk_id not in available_disks:
                    raise TaskException(errno.EBUSY, f'Disk {vdev["vdev"]["path"]} is not available to use')

                subtasks.append(self.run_subtask(
                    'disk.format.gpt',
                    disk_id,
                    'freebsd-zfs',
                    {
                        'blocksize': params.get('blocksize', 4096),
                        'swapsize': params.get('swapsize', swapsize)
                    }
                ))

            self.join_subtasks(*subtasks)

            if encryption['key'] or encryption['hashed_password']:
                subtasks = []
                for vdev, group in iterate_vdevs(new_vdevs):
                    subtasks.append(self.run_subtask(
                        'disk.geli.init',
                        self.dispatcher.call_sync('disk.path_to_id', vdev['path']),
                        {
                            'key': encryption['key'],
                            'password': password
                        }
                    ))
                self.join_subtasks(*subtasks)

                if encryption['slot'] != 0:
                    subtasks = []
                    for vdev, group in iterate_vdevs(new_vdevs):
                        subtasks.append(self.run_subtask(
                            'disk.geli.ukey.set',
                            self.dispatcher.call_sync('disk.path_to_id', vdev['path']),
                            {
                                'key': encryption['key'],
                                'password': password,
                                'slot': 1
                            }
                        ))
                    self.join_subtasks(*subtasks)

                    subtasks = []
                    for vdev, group in iterate_vdevs(new_vdevs):
                        subtasks.append(self.run_subtask(
                            'disk.geli.ukey.del',
                            self.dispatcher.call_sync('disk.path_to_id', vdev['path']),
                            0
                        ))
                    self.join_subtasks(*subtasks)

                vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})
                if vol.get('providers_presence', 'NONE') != 'NONE':
                    subtasks = []
                    for vdev, group in iterate_vdevs(new_vdevs):
                        subtasks.append(self.run_subtask(
                            'disk.geli.attach',
                            self.dispatcher.call_sync('disk.path_to_id', vdev['path']),
                            {
                                'key': encryption['key'],
                                'password': password
                            }
                        ))
                    self.join_subtasks(*subtasks)

            new_vdevs_gptids = convert_topology_to_gptids(self.dispatcher, new_vdevs)

            for vdev in updated_vdevs:
                vdev['vdev']['path'] = get_disk_gptid(self.dispatcher, vdev['vdev']['path'])

            self.run_subtask_sync(
                'zfs.pool.extend',
                id,
                new_vdevs_gptids,
                updated_vdevs,
                progress_callback=self.set_progress
            )

            volume['topology'] = new_topology
            for vdev, _ in iterate_vdevs(volume['topology']):
                vdev['disk_id'] = self.dispatcher.call_sync(
                    'disk.query',
                    [('path', '=', vdev['path']), ('online', '=', True)],
                    {'single': True, 'select': 'id'}
                )

            self.datastore.update('volumes', volume['id'], volume)
            self.dispatcher.dispatch_event('volume.changed', {
                'operation': 'update',
                'ids': [volume['id']]
            })

        if 'auto_unlock' in updated_params:
            auto_unlock = updated_params.get('auto_unlock', False)
            if auto_unlock and (not volume.get('key_encrypted') or volume.get('password_encrypted')):
                raise TaskException(
                    errno.EINVAL,
                    'Automatic volume unlock can be selected for volumes using only key based encryption.'
                )

            volume['auto_unlock'] = auto_unlock

            self.datastore.update('volumes', volume['id'], volume)
            self.dispatcher.dispatch_event('volume.changed', {
                'operation': 'update',
                'ids': [volume['id']]
            })


@description("Imports previously exported volume")
@accepts(str, h.one_of(str, None), h.object(), h.ref('VolumeImportParams'), h.one_of(Password, None))
@returns(str)
class VolumeImportTask(Task):
    @classmethod
    def early_describe(cls):
        return "Importing a volume"

    def describe(self, id, new_name=None, params=None, enc_params=None, password=None):
        return TaskDescription("Importing the volume {name}", name=new_name or id)

    def verify(self, id, new_name=None, params=None, enc_params=None, password=None):
        enc_params = enc_params or {}

        if enc_params.get('key') or enc_params.get('key_fd') or password:
            if enc_params.get('auto_unlock') and password:
                raise VerifyException(errno.EINVAL, 'Password protected volume cannot be automatically unlocked')

            disks = enc_params.get('disks', None)
            if disks is None:
                raise VerifyException(
                    errno.EINVAL, 'List of disks must be provided for import')
            else:
                if isinstance(disks, str):
                    disks = [disks]

                result = []
                for d in disks:
                    try:
                        result.append('disk:{}'.format(self.dispatcher.call_sync('disk.path_to_id', d)))
                    except RpcException:
                        pass
                return result
        else:
            return self.verify_subtask('zfs.pool.import', id, new_name)

    def run(self, id, new_name=None, params=None, enc_params=None, password=None):
        if self.datastore.exists('volumes', ('id', '=', id)):
            raise TaskException(
                errno.ENOENT,
                'Volume with id {0} already exists'.format(id)
            )

        if self.datastore.exists('volumes', ('id', '=', new_name)):
            raise TaskException(
                errno.ENOENT,
                'Volume with name {0} already exists'.format(new_name)
            )

        enc_params = enc_params or {}

        with self.dispatcher.get_lock('volumes'):
            key = enc_params.get('key')
            if not key:
                key_fd = enc_params.get('key_fd')
                if key_fd:
                    with os.fdopen(key_fd.fd, 'rb') as key_file:
                        raw_key = key_file.read()
                        try:
                            key = raw_key.decode('utf-8')
                        except UnicodeDecodeError:
                            key = base64.b64encode(raw_key).decode('utf-8')

            slot = 0

            if password:
                salt, digest = get_digest(password)
            else:
                salt = None
                digest = None

            if key or password:
                disks = enc_params.get('disks', [])
                if isinstance(disks, str):
                    disks = [disks]

                attach_params = {'key': key, 'password': password}
                for dname in disks:
                    disk_id = self.dispatcher.call_sync('disk.path_to_id', dname)
                    self.run_subtask_sync('disk.geli.attach', disk_id, attach_params)

            new_name, guid = self.run_subtask_sync('zfs.pool.import', id, new_name, params)
            mountpoint = os.path.join(VOLUMES_ROOT, new_name)
            self.run_subtask_sync(
                'zfs.update',
                new_name,
                {'mountpoint': {'value': mountpoint}}
            )

            self.run_subtask_sync('zfs.mount', new_name, True)

            new_topology = self.dispatcher.call_sync(
                'zfs.pool.query',
                [('id', '=', new_name)],
                {'single': True, 'select': 'groups'}
            )

            simplify_topology(new_topology)

            if key or password:
                slots_state = self.dispatcher.call_sync('disk.key_slots_by_paths', disks)
                slot_0_cnt = 0
                slot_1_cnt = 0
                for s in slots_state:
                    if s['key_slot']:
                        slot_1_cnt += 1
                    else:
                        slot_0_cnt += 1

                slot = int(slot_1_cnt > slot_0_cnt)

                if slot_0_cnt and slot_1_cnt:
                    for dname in disks:
                        used_slot = first_or_default(lambda s: s['path'] == dname, slots_state, {}).get('key_slot')
                        if used_slot != slot:
                            disk_id = self.dispatcher.call_sync('disk.path_to_id', dname)
                            self.run_subtask_sync('disk.geli.ukey.set', disk_id, {
                                'key': key,
                                'password': password,
                                'slot': slot
                            })
                            self.run_subtask_sync('disk.geli.ukey.del', disk_id, used_slot)

            for vdev, _ in iterate_vdevs(new_topology):
                vdev['disk_id'] = self.dispatcher.call_sync(
                    'disk.query',
                    [('status.data_partition_path', '=', vdev['path']), ('online', '=', True)],
                    {'single': True, 'select': 'id'}
                )

            new_id = self.datastore.insert('volumes', {
                'id': new_name,
                'guid': guid,
                'type': 'zfs',
                'topology': new_topology,
                'encryption': {
                    'key': key,
                    'hashed_password': digest,
                    'salt': salt,
                    'slot': slot if key or password else None},
                'key_encrypted': True if key else False,
                'password_encrypted': True if password else False,
                'auto_unlock': enc_params.get('auto_unlock', False),
                'mountpoint': mountpoint
            })

            self.dispatcher.dispatch_event('volume.changed', {
                'operation': 'create',
                'ids': [new_id]
            })

        self.dispatcher.run_hook('volume.post_attach', {'name': new_name})
        return new_name


@description("Imports non-ZFS disk contents into existing volume")
@accepts(str, str, h.one_of(str, None))
class VolumeDiskImportTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Importing disk into volume"

    def describe(self, src, dest_path, fstype=None):
        return TaskDescription("Importing disk {src} into {dst} path", src=src, dst=dest_path)

    def verify(self, src, dest_path, fstype=None):
        disk = self.dispatcher.call_sync('disk.partition_to_disk', src)
        if not disk:
            raise VerifyException(errno.ENOENT, "Partition {0} not found".format(src))

        return ['disk:{0}'.format(disk)]

    def run(self, src, dest_path, fstype=None):
        if not fstype:
            try:
                fstype, _ = fstyp(src)
            except SubprocessException:
                raise TaskException(errno.EINVAL, 'Cannot figure out filesystem type')

        if fstype == 'ntfs':
            try:
                bsd.kld.kldload('/boot/kernel/fuse.ko')
            except FileExistsError:
                # This can only arise if the module was already mounted
                # and we tried to remount it, in which case lets just proceed
                pass
            except OSError as err:
                raise TaskException(err.errno, str(err))

        src_mount = tempfile.mkdtemp()

        try:
            bsd.nmount(source=src, fspath=src_mount, fstype=fstype)
        except OSError as err:
            raise TaskException(err.errno, "Cannot mount disk: {0}".format(str(err)))

        self.set_progress(0, "Counting files...")
        self.nfiles = count_files(src_mount)
        self.copied = 0

        def callback(srcfile, dstfile):
            self.copied += 1
            self.set_progress(self.copied / self.nfiles * 100, "Copying {0}".format(os.path.basename(srcfile)))

        failures = []

        try:
            copytree(src_mount, dest_path, progress_callback=callback)
        except shutil.Error as err:
            failures = list(err)

        try:
            bsd.unmount(src_mount.encode('utf8'), bsd.MountFlags.FORCE)
        except OSError:
            pass

        bsd.kld.kldunload('fuse')
        os.rmdir(src_mount)
        return failures


@description("Exports active volume")
@accepts(str, h.one_of(None, FileDescriptor))
class VolumeDetachTask(Task):
    @classmethod
    def early_describe(cls):
        return "Detaching a volume"

    def describe(self, id, key_fd=None):
        return TaskDescription("Detaching the volume {name}", name=id)

    def verify(self, id, key_fd=None):
        vol = self.datastore.get_by_id('volumes', id)
        if not vol:
            raise VerifyException(errno.ENOENT, 'Volume {0} not found'.format(id))

        return [f'volume:{id}']

    def run(self, id, key_fd=None):
        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})
        if not vol:
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        disks = get_disks(vol['topology'])
        self.dispatcher.run_hook('volume.pre_detach', {'name': id})

        try:
            self.run_subtask_sync('zfs.umount', id)
            self.run_subtask_sync('zfs.pool.export', id)
        except RpcException as err:
            if err.code == errno.EBUSY:
                # Find out what's holding unmount or destroy
                files = list(itertools.chain(
                    self.dispatcher.call_sync('filesystem.get_open_files', vol['mountpoint']),
                    self.dispatcher.call_sync('filesystem.get_open_files', os.path.join('/dev/zvol', vol['id'])),
                ))

                if len(files) == 1:
                    raise TaskException(
                        errno.EBUSY,
                        'Volume is in use by {process_name} (pid {pid}, path {path})'.format(**files[0]),
                        extra=files
                    )
                else:
                    raise TaskException(
                        errno.EBUSY,
                        'Volume is in use by {0} processes'.format(len(files)),
                        extra=files
                    )
            else:
                raise

        self.datastore.delete('volumes', vol['id'])

        encryption = vol.get('encryption')
        if encryption['key'] or encryption['hashed_password']:
            subtasks = []
            for dname, _ in disks:
                disk_id = self.dispatcher.call_sync('disk.path_to_id', dname)
                subtasks.append(self.run_subtask('disk.geli.detach', disk_id))
            self.join_subtasks(*subtasks)

        self.dispatcher.dispatch_event('volume.changed', {
            'operation': 'delete',
            'ids': [id]
        })

        if encryption['key']:
            if not key_fd:
                self.add_warning(TaskWarning(
                    errno.EPERM,
                    'Detached volume {0} was encrypted! Save key {1} to be able to import the volume later.'.format(
                        id,
                        encryption['key']
                    )
                ))
            else:
                with os.fdopen(key_fd.fd, 'wb') as key_file:
                    key_file.write(encryption['key'])


@description("Upgrades volume to newest ZFS version")
@accepts(str)
class VolumeUpgradeTask(Task):
    @classmethod
    def early_describe(cls):
        return "Upgrading a volume"

    def describe(self, id):
        return TaskDescription("Upgrading the volume {name}", name=id)

    def verify(self, id):
        return [f'volume:{id}']

    def run(self, id):
        vol = self.datastore.get_by_id('volumes', id)
        if not vol:
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        self.run_subtask_sync('zfs.pool.upgrade', id)
        self.dispatcher.dispatch_event('volume.changed', {
            'operation': 'update',
            'ids': [vol['id']]
        })


@description('Replaces a disk in active volume')
@accepts(str, str, str, h.one_of(Password, None))
class VolumeReplaceTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Replacing a disk in a volume"

    def describe(self, id, vdev, disk_id, password=None):
        return TaskDescription("Replacing disk a in volume {name}", name=id)

    def verify(self, id, vdev, disk_id, password=None):
        return [f'volume:{id}', f'disk:{disk_id}']

    def run(self, id, vdev, path, password=None):
        swapsize = self.configstore.get('system.swapondrive') * 1024
        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})
        if not vol:
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        vdev_config = vdev_by_guid(vol['topology'], vdev)

        disk = self.dispatcher.call_sync('disk.query', [('id', '=', path), ('online', '=', True)], {'single': True})
        spares = vol['topology'].get('spare', [])

        if not disk:
            raise TaskException(errno.ENOENT, 'Cannot replace with {0}: disk not found or not online'.format(path))

        if first_or_default(lambda v: v['path'] == os.path.join('/dev', disk['path']), spares):
            # New disk is a spare. No need to format it, but we need to remove it from the spares
            # list when resilver finishes
            spare = True
        else:
            spare = False
            self.run_subtask_sync('disk.format.gpt', disk['id'], 'freebsd-zfs', {'swapsize': swapsize})
            disk = self.dispatcher.call_sync('disk.query', [('path', '=', disk['path'])], {'single': True})

        if vol.get('key_encrypted') or vol.get('password_encrypted'):
            encryption = vol['encryption']
            if vol.get('password_encrypted'):
                if not is_password(
                        password,
                        encryption.get('salt', ''),
                        encryption.get('hashed_password', '')
                ):
                    raise TaskException(
                        errno.EINVAL,
                        'Password provided for volume {0} is not valid'.format(id)
                    )

            self.run_subtask_sync('disk.geli.init', disk['id'], {
                'key': encryption['key'],
                'password': password
            })

            if encryption['slot'] != 0:
                self.run_subtask_sync('disk.geli.ukey.set', disk['id'], {
                    'key': encryption['key'],
                    'password': password,
                    'slot': 1
                })

                self.run_subtask_sync('disk.geli.ukey.del', disk['id'], 0)

            if vol.get('providers_presence', 'NONE') != 'NONE':
                self.run_subtask_sync('disk.geli.attach', disk['id'], {
                    'key': encryption['key'],
                    'password': password
                })

        self.join_subtasks(
            self.run_subtask(
                'zfs.pool.replace',
                id, vdev, {
                    'type': 'disk',
                    'path': get_disk_gptid(self.dispatcher, disk['path'])
                },
                progress_callback=self.set_progress
            )
        )

        if spare:
            self.run_subtask_sync('zfs.pool.detach', id, vdev)

        new_topology = self.dispatcher.call_sync(
            'volume.query',
            [('id', '=', id)],
            {'single': True, 'select': 'topology'}
        )
        if new_topology:
            vol = self.datastore.get_by_id('volumes', id)
            simplify_topology(new_topology)
            vol['topology'] = new_topology

        self.datastore.update('volumes', id, vol)

        if vol.get('key_encrypted') or vol.get('password_encrypted'):
            if vdev_config and self.dispatcher.call_sync('disk.is_geli_provider', vdev_config['path']):
                disk_id = self.dispatcher.call_sync('disk.path_to_id', vdev_config['path'])
                self.run_subtask_sync('disk.geli.kill', disk_id)

        self.dispatcher.dispatch_event('volume.changed', {
            'operation': 'update',
            'ids': [id]
        })


@description('Replaces failed disk in active volume')
@accepts(str, str, h.one_of(Password, None))
class VolumeAutoReplaceTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Replacing failed disk in a volume"

    def describe(self, id, failed_vdev, password=None):
        vdev_path = None
        try:
            vdev = self.dispatcher.call_sync('volume.vdev_by_guid', id, failed_vdev)
            if vdev:
                vdev_path = vdev['path']
        except RpcException:
            pass

        return TaskDescription(
            "Replacing the failed disk {vdev} in the volume {name}",
            name=id,
            vdev=vdev_path or failed_vdev
        )

    def verify(self, id, failed_vdev, password=None):
        return [f'volume:{id}']

    def run(self, id, failed_vdev, password=None):
        swapsize = self.configstore.get('system.swapondrive') * 1024
        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})
        if not vol:
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        if vol['key_encrypted'] or vol['password_encrypted']:
            raise TaskException(errno.EPERM, 'Cannot autoreplace disk in an encrypted volume')

        empty_disks = self.dispatcher.call_sync('disk.query', [
            ('status.empty', '=', True),
            ('online', '=', True)
        ])

        vdev = self.dispatcher.call_sync('zfs.pool.vdev_by_guid', id, failed_vdev)
        minsize = vdev['stats']['size']

        # First, try to find spare assigned to the pool
        spares = vol['topology'].get('spare', [])
        for spare in spares:
            disk = self.dispatcher.call_sync('disk.query', [('path', '=', spare['path'])], {'single': True})
            if not disk or not disk['online']:
                continue

            self.run_subtask_sync('volume.vdev.replace', id, failed_vdev, disk['id'])
            return

        # Now into global hot-sparing mode
        if self.configstore.get('storage.hotsparing.strong_match'):
            pass
        else:
            matching_disks = sorted(empty_disks, key=lambda d: d['mediasize'])
            disk = first_or_default(lambda d: d['mediasize'] >= minsize, matching_disks)
            if disk:
                self.run_subtask_sync('disk.format.gpt', disk['id'], 'freebsd-zfs', {'swapsize': swapsize})
                self.run_subtask_sync(
                    'volume.vdev.replace',
                    id, failed_vdev, disk['id'], password,
                    progress_callback=self.set_progress
                )
                return

        raise TaskException(errno.EBUSY, 'No matching disk to be used as spare found')


@description("Locks encrypted ZFS volume")
@accepts(str)
class VolumeLockTask(Task):
    @classmethod
    def early_describe(cls):
        return "Locking encrypted volume"

    def describe(self, id):
        return TaskDescription("Locking the encrypted volume {name}", name=id)

    def verify(self, id):
        return [f'volume:{id}']

    def run(self, id):
        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})
        if not vol:
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        if not (vol.get('key_encrypted') or vol.get('password_encrypted')):
            raise TaskException(errno.EINVAL, 'Volume {0} is not encrypted'.format(id))

        if vol.get('providers_presence', 'NONE') == 'NONE':
            raise TaskException(errno.EINVAL, 'Volume {0} does not have any unlocked providers'.format(id))

        self.dispatcher.run_hook('volume.pre_detach', {'name': id})

        with self.dispatcher.get_lock('volumes'):
            self.run_subtask_sync('zfs.umount', id)
            self.run_subtask_sync('zfs.pool.export', id)

            subtasks = []
            for vdev, _ in iterate_vdevs(vol['topology']):
                if vol['providers_presence'] == 'PART':
                    vdev_conf = self.dispatcher.call_sync('disk.get_disk_config', vdev)
                    if vdev_conf.get('encrypted'):
                        subtasks.append(self.run_subtask(
                            'disk.geli.detach',
                            self.dispatcher.call_sync('disk.path_to_id', vdev['path'])
                        ))
                else:
                    subtasks.append(self.run_subtask(
                        'disk.geli.detach',
                        self.dispatcher.call_sync('disk.path_to_id', vdev['path'])
                    ))
            self.join_subtasks(*subtasks)

            self.dispatcher.dispatch_event('volume.changed', {
                'operation': 'update',
                'ids': [vol['id']]
            })


@description("Imports VMs, shares and system dataset from a volume")
@accepts(
    str,
    h.enum(str, ['all', 'vms', 'shares', 'system'])
)
class VolumeAutoImportTask(Task):
    @classmethod
    def early_describe(cls):
        return "Importing services from a volume"

    def describe(self, volume, scope):
        return TaskDescription("Importing {scope} services from the volume {name}", name=volume, scope=scope)

    def verify(self, volume, scope):
        return [f'volume:{volume}']

    def run(self, volume, scope):
        if not self.datastore.exists('volumes', ('id', '=', volume)):
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(volume))

        with self.dispatcher.get_lock('volumes'):
            vol = self.dispatcher.call_sync('volume.query', [('id', '=', volume)], {'single': True})
            share_types = self.dispatcher.call_sync('share.supported_types')
            imported = {
                'shares': [],
                'vms': [],
                'system': []
            }

            for root, dirs, files in os.walk(vol['mountpoint']):
                for file in files:
                    config_name = re.match('(\.config-)(.*)(\.json)', file)
                    config_path = os.path.join(root, file)
                    if config_name:
                        try:
                            config = load_config(root, config_name.group(2))
                        except ValueError:
                            self.add_warning(
                                TaskWarning(
                                    errno.EINVAL,
                                    'Cannot read {0}. This file is not a valid JSON file'.format(config_path)
                                )
                            )
                            continue

                        item_type = config.get('type', 'VM')
                        if scope in ['all', 'shares'] and item_type in share_types:
                            try:
                                self.run_subtask_sync(
                                    'share.import',
                                    root,
                                    config.get('name', ''),
                                    item_type
                                )

                                imported['shares'].append(
                                {
                                    'path': config_path,
                                    'type': item_type,
                                    'name': config.get('name', '')
                                })
                            except RpcException as err:
                                self.add_warning(
                                    TaskWarning(
                                        err.code,
                                        'Share import from {0} failed. Message: {1}'.format(
                                            config_path,
                                            err.message
                                        )
                                    )
                                )
                                continue
                        elif scope in ['all', 'vms']:
                            try:
                                self.run_subtask_sync(
                                    'vm.import',
                                    config.get('name', ''),
                                    volume
                                )

                                imported['vms'].append(
                                    {
                                        'type': item_type,
                                        'name': config.get('name', '')
                                    }
                                )
                            except RpcException as err:
                                self.add_warning(
                                    TaskWarning(
                                        err.code,
                                        'VM import from {0} failed. Message: {1}'.format(
                                            config_path,
                                            err.message
                                        )
                                    )
                                )
                                continue
                        else:
                            self.add_warning(
                                TaskWarning(
                                    errno.EINVAL,
                                    'Import from {0} failed because {1} is unsupported share/VM type'.format(
                                        config_path,
                                        item_type
                                    )
                                )
                            )
                            continue

            if scope in ['all', 'system']:
                if self.dispatcher.call_sync('zfs.dataset.query', [('volume', '=', volume), ('name', '~', '.system')], {'single': True}):
                    try:
                        self.run_subtask_sync(
                            'system_dataset.import',
                            volume
                        )
                        status = self.dispatcher.call_sync('system_dataset.status')
                        imported['system'].append(
                            {
                                'id': status['id'],
                                'volume': volume
                            }
                        )
                    except RpcException as err:
                        self.add_warning(
                            TaskWarning(
                                err.code,
                                'System dataset import from {0} failed. Message: {1}'.format(
                                    volume,
                                    err.message
                                )
                            )
                        )

        return imported


@description("Unlocks encrypted ZFS volume")
@accepts(str, h.one_of(Password, None), h.object())
class VolumeUnlockTask(Task):
    @classmethod
    def early_describe(cls):
        return "Unlocking encrypted volume"

    def describe(self, id, password=None, params=None):
        return TaskDescription("Unlocking the encrypted volume {name}", name=id)

    def verify(self, id, password=None, params=None):
        topology = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True, 'select': 'topology'})
        return [f'disk:{v["disk_id"]}' for v, _ in iterate_vdevs(topology)]

    def run(self, id, password=None, params=None):
        with self.dispatcher.get_lock('volumes'):
            vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})

            encryption = vol.get('encryption')

            if not (vol.get('key_encrypted') or vol.get('password_encrypted')):
                raise TaskException(errno.EINVAL, 'Volume {0} is not encrypted'.format(id))

            if vol.get('providers_presence', 'ALL') == 'ALL':
                raise TaskException(errno.EINVAL, 'Volume {0} does not have any locked providers'.format(id))

            if encryption['hashed_password']:
                if password is None:
                    raise TaskException(
                        errno.EINVAL,
                        'Volume {0} is protected with password. Provide a valid password.'.format(id)
                    )
                if not is_password(password,
                                   encryption.get('salt', ''),
                                   encryption.get('hashed_password', '')):
                    raise TaskException(errno.EINVAL, 'Password provided for volume {0} unlock is not valid'.format(id))

            for vdev, _ in iterate_vdevs(vol['topology']):
                if not self.dispatcher.call_sync(
                        'disk.query',
                        [('id', '=', vdev['disk_id']), ('online', '=', True)],
                        {'count': True}):
                    raise TaskException(
                        errno.ENOENT,
                        'Cannot decrypt {0} - disk {1} not found. Old path was {2}'.format(
                            id,
                            vdev['disk_id'],
                            vdev['path']
                        )
                    )

            subtasks = []
            for vdev, _ in iterate_vdevs(vol['topology']):
                path = self.dispatcher.call_sync(
                    'disk.query',
                    [('id', '=', vdev.get('disk_id', ''))],
                    {'single': True, 'select': 'path'}
                )
                if not path:
                    path = vdev['path']

                if vol['providers_presence'] == 'PART':
                    vdev_conf = self.dispatcher.call_sync('disk.get_disk_config', path)
                    if not vdev_conf.get('encrypted'):
                        subtasks.append(self.run_subtask(
                            'disk.geli.attach',
                            self.dispatcher.call_sync('disk.path_to_id', path),
                            {
                                'key': vol['encryption']['key'],
                                'password': password
                            }
                        ))
                else:
                    subtasks.append(self.run_subtask(
                        'disk.geli.attach',
                        self.dispatcher.call_sync('disk.path_to_id', path),
                        {
                            'key': vol['encryption']['key'],
                            'password': password
                        }
                    ))
            self.join_subtasks(*subtasks)

            self.run_subtask_sync('zfs.pool.import', vol['guid'], id, params)

            if vol['mountpoint']:
                self.run_subtask_sync(
                    'zfs.update',
                    id,
                    {'mountpoint': {'value': vol['mountpoint']}}
                )

            self.run_subtask_sync('zfs.mount', id, True)

            self.dispatcher.dispatch_event('volume.changed', {
                'operation': 'update',
                'ids': [vol['id']]
            })

        self.dispatcher.run_hook('volume.post_attach', {'name': id})


@description("Generates and sets new key for encrypted ZFS volume")
@accepts(str, bool, h.one_of(Password, None))
class VolumeRekeyTask(Task):
    @classmethod
    def early_describe(cls):
        return "Regenerating the keys of encrypted volume"

    def describe(self, id, key_encrypted, password=None):
        return TaskDescription("Regenerating the keys of the encrypted volume {name}", name=id)

    def verify(self, id, key_encrypted, password=None):
        return [f'volume:{id}']

    def run(self, id, key_encrypted, password=None):
        if not self.datastore.exists('volumes', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})

        if not (vol.get('key_encrypted') or vol.get('password_encrypted')):
            raise TaskException(errno.EINVAL, 'Volume {0} is not encrypted'.format(id))

        if vol.get('providers_presence', 'NONE') != 'ALL':
            raise TaskException(errno.EINVAL, 'Every provider associated with volume {0} must be online'.format(id))

        with self.dispatcher.get_lock('volumes'):
            vol = self.datastore.get_by_id('volumes', id)
            encryption = vol.get('encryption')
            disks = self.dispatcher.call_sync('volume.get_volume_disks', id)

            if key_encrypted:
                key = base64.b64encode(os.urandom(256)).decode('utf-8')
            else:
                key = None

            slot = 0 if encryption['slot'] is 1 else 1

            if password:
                salt, digest = get_digest(password)
            else:
                salt = None
                digest = None

            subtasks = []
            disk_ids = []
            for dname in disks:
                disk_id = self.dispatcher.call_sync('disk.path_to_id', dname)
                disk_ids.append(disk_id)
                subtasks.append(self.run_subtask('disk.geli.ukey.set', disk_id, {
                    'key': key,
                    'password': password,
                    'slot': slot
                }))
            self.join_subtasks(*subtasks)

            encryption = {
                'key': key,
                'hashed_password': digest,
                'salt': salt,
                'slot': slot}

            vol['encryption'] = encryption
            vol['key_encrypted'] = key_encrypted
            vol['password_encrypted'] = True if password else False
            if password:
                vol['auto_unlock'] = False

            self.datastore.update('volumes', vol['id'], vol)

            slot = 0 if encryption['slot'] is 1 else 1

            subtasks = []
            for disk_id in disk_ids:
                subtasks.append(self.run_subtask('disk.geli.ukey.del', disk_id, slot))
            self.join_subtasks(*subtasks)

            self.dispatcher.dispatch_event('volume.changed', {
                'operation': 'update',
                'ids': [vol['id']]
            })


@description("Creates a backup of Master Keys of encrypted volume")
@accepts(str, FileDescriptor)
@returns(Password)
class VolumeBackupKeysTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating a backup of the keys of encrypted volume"

    def describe(self, id, fd):
        return TaskDescription("Creating a backup of the keys of the encrypted volume {name}", name=id)

    def verify(self, id, fd):
        return [f'volume:{id}']

    def run(self, id, fd):
        if not self.datastore.exists('volumes', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})

        if not (vol.get('key_encrypted') or vol.get('password_encrypted')):
            raise TaskException(errno.EINVAL, 'Volume {0} is not encrypted'.format(id))

        if vol.get('providers_presence', 'NONE') != 'ALL':
            raise TaskException(errno.EINVAL, 'Every provider associated with volume {0} must be online'.format(id))

        if not fd:
            raise TaskException(errno.EINVAL, 'Output file is not specified')

        with self.dispatcher.get_lock('volumes'):
            disks = self.dispatcher.call_sync('volume.get_volume_disks', id)
            out_data = {}

            subtasks = []
            for dname in disks:
                disk_id = self.dispatcher.call_sync('disk.path_to_id', dname)
                subtasks.append(self.run_subtask('disk.geli.mkey.backup', disk_id))
            output = self.join_subtasks(*subtasks)

        for result in output:
            out_data[result['disk']] = result

        password = Password(str(uuid.uuid4()))
        enc_data = fernet_encrypt(password, dumps(out_data).encode('utf-8'))

        with os.fdopen(fd.fd, 'wb') as out_file:
            out_file.write(enc_data)

        return password


@description("Creates a backup file of Master Keys of encrypted volume")
@accepts(str, str)
@returns(Password)
class VolumeBackupKeysToFileTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating a backup of the keys of encrypted volume"

    def describe(self, id, out_path=None):
        return TaskDescription("Creating a backup of the keys of the encrypted volume {name}", name=id)

    def verify(self, id, out_path=None):
        return [f'volume:{id}']

    def run(self, id, out_path=None):
        with open(out_path, 'wb') as out_file:
            password = self.run_subtask_sync(
                'volume.keys.backup',
                id,
                FileDescriptor(out_file.fileno())
            )

        return password


@description("Loads a backup of Master Keys of encrypted volume")
@accepts(str, FileDescriptor, h.one_of(Password, None))
class VolumeRestoreKeysTask(Task):
    @classmethod
    def early_describe(cls):
        return "Uploading the keys from backup to encrypted volume"

    def describe(self, id, fd, password=None):
        return TaskDescription("Uploading the keys from backup to the encrypted volume {name}", name=id)

    def verify(self, id, fd, password=None):
        return [f'volume:{id}']

    def run(self, id, fd, password=None):
        if not self.datastore.exists('volumes', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})

        if not (vol.get('key_encrypted') or vol.get('password_encrypted')):
            raise TaskException(errno.EINVAL, 'Volume {0} is not encrypted'.format(id))

        if vol.get('providers_presence', 'ALL') != 'NONE':
            raise TaskException(errno.EINVAL, 'Volume {0} cannot have any online providers'.format(id))

        if not fd:
            raise TaskException(errno.EINVAL, 'Input file is not specified')

        if password is None:
            raise TaskException(errno.EINVAL, 'Password is not specified')

        vol = self.datastore.get_by_id('volumes', id)
        with os.fdopen(fd.fd, 'rb') as in_file:
            enc_data = in_file.read()

        try:
            json_data = fernet_decrypt(password, enc_data)
        except InvalidToken:
            raise TaskException(errno.EINVAL, 'Provided password do not match backup file')

        data = loads(json_data.decode('utf-8'), 'utf-8')

        with self.dispatcher.get_lock('volumes'):
            subtasks = []
            for dname, dgroup in get_disks(vol['topology']):
                disk = data.get(dname, None)
                if disk is None:
                    raise TaskException(errno.EINVAL, 'Disk {0} is not a part of volume {1}'.format(disk['disk'], id))

                disk_id = self.dispatcher.call_sync('disk.path_to_id', dname)

                subtasks.append(self.run_subtask('disk.geli.mkey.restore', disk_id, disk))

            self.join_subtasks(*subtasks)


@description("Loads a backup file of Master Keys of encrypted volume")
@accepts(str, str, h.one_of(Password, None))
class VolumeRestoreKeysFromFileTask(Task):
    @classmethod
    def early_describe(cls):
        return "Uploading the keys from backup to encrypted volume"

    def describe(self, id, in_path, password=None):
        return TaskDescription("Uploading the keys from backup to the encrypted volume {name}", name=id)

    def verify(self, id, in_path, password=None):
        return [f'volume:{id}']

    def run(self, id, in_path, password=None):
        with open(in_path, 'rb') as in_file:
            self.run_subtask_sync(
                'volume.keys.restore',
                id,
                FileDescriptor(in_file.fileno()),
                password
            )


@description("Scrubs the volume")
@accepts(str)
class VolumeScrubTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Performing a scrub of a volume"

    def describe(self, id):
        return TaskDescription("Performing a scrub of the volume {name}", name=id)

    def verify(self, id):
        return []

    def abort(self):
        self.abort_subtasks()

    def run(self, id):
        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})
        if not vol:
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        self.run_subtask_sync(
            'zfs.pool.scrub', id,
            progress_callback=self.set_progress
        )


@description("Makes vdev in a volume offline")
@accepts(str, str)
class VolumeOfflineVdevTask(Task):
    @classmethod
    def early_describe(cls):
        return "Turning offline a disk of a volume"

    def describe(self, id, vdev_guid):
        vdev = self.dispatcher.call_sync('volume.vdev_by_guid', id, vdev_guid)
        vdev_path = None
        if vdev:
            vdev_path = vdev['path']

        return TaskDescription(
            "Turning offline the {disk} disk of the volume {name}",
            name=id,
            disk=vdev_path or vdev_guid
        )

    def verify(self, id, vdev_guid):
        return [f'volume:{id}']

    def run(self, id, vdev_guid):
        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})
        if not vol:
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        self.run_subtask_sync(
            'zfs.pool.offline_disk',
            id,
            vdev_guid
        )


@description("Makes vdev in a volume online")
@accepts(str, str)
class VolumeOnlineVdevTask(Task):
    @classmethod
    def early_describe(cls):
        return "Turning online a disk of a volume"

    def describe(self, id, vdev_guid):
        vdev = self.dispatcher.call_sync('volume.vdev_by_guid', id, vdev_guid)
        vdev_path = None
        if vdev:
            vdev_path = vdev['path']

        return TaskDescription(
            "Turning online the {disk} disk of the volume {name}",
            name=id,
            disk=vdev_path or vdev_guid
        )

    def verify(self, id, vdev_guid):
        return [f'volume:{id}']

    def run(self, id, vdev_guid):
        vol = self.dispatcher.call_sync('volume.query', [('id', '=', id)], {'single': True})
        if not vol:
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(id))

        self.run_subtask_sync(
            'zfs.pool.online_disk',
            id,
            vdev_guid
        )


@description("Creates a dataset in an existing volume")
@accepts(h.all_of(
    h.ref('VolumeDataset'),
    h.required('id', 'volume')
))
class DatasetCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating a dataset"

    def describe(self, dataset):
        return TaskDescription("Creating the dataset {name}", name=dataset['id'])

    def verify(self, dataset):
        return [f'volume:{dataset["volume"]}']

    def run(self, dataset):
        if not self.datastore.exists('volumes', ('id', '=', dataset['volume'])):
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(dataset['volume']))

        props = {}
        normalize(dataset, {
            'type': 'FILESYSTEM',
            'permissions_type': 'PERM',
            'mounted': True,
            'hidden': False,
            'properties': {},
            'metadata': {}
        })

        for name, value in dataset['metadata']:
            props[name] = {'value': value}

        if dataset['id'].startswith('.'):
            dataset['hidden'] = True

        if dataset['type'] == 'FILESYSTEM':
            props = {
                'org.freenas:permissions_type': {'value': dataset['permissions_type']},
                'org.freenas:hidden': {'value': 'yes' if dataset['hidden'] else 'no'},
                'aclmode': {'value': 'discard_chmod' if dataset['permissions_type'] == 'ACL' else 'passthrough'}
            }

        if dataset['type'] == 'VOLUME':
            props['volsize'] = {'value': str(dataset['volsize'])}

        props.update(exclude(
            dataset['properties'],
            'used', 'usedbydataset', 'usedbysnapshots', 'usedbychildren', 'logicalused', 'logicalreferenced',
            'origin', 'written', 'usedbyrefreservation', 'referenced', 'available', 'compressratio', 'refcompressratio'
        ))

        props.update({
            'org.freenas:uuid': {'value': str(uuid.uuid4())}
        })

        self.run_subtask_sync(
            'zfs.create_dataset',
            dataset['id'],
            dataset['type'],
            props
        )

        if dataset['mounted'] and dataset['type'] == 'FILESYSTEM':
            self.run_subtask_sync('zfs.mount', dataset['id'])

        if dataset['permissions_type'] == 'ACL':
            fs_path = self.dispatcher.call_sync('volume.get_dataset_path', dataset['id'])
            self.run_subtask_sync('file.set_permissions', fs_path, {'acl': DEFAULT_ACLS}, True)

        if dataset.get('permissions'):
            path = os.path.join(VOLUMES_ROOT, dataset['id'])
            self.run_subtask_sync('file.set_permissions', path, dataset['permissions'])

        wait_for_cache(self.dispatcher, 'volume.dataset', 'create', dataset['id'])
        return dataset['id']


@description("Deletes an existing Dataset from a Volume")
@accepts(str)
class DatasetDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting a dataset"

    def describe(self, id):
        return TaskDescription("Deleting the dataset {name}", name=id)

    def verify(self, id):
        pool_name, _ = split_dataset(id)
        return [f'volume:{pool_name}']

    def run(self, id):
        pool_name, _, ds = id.partition('/')
        if not self.datastore.exists('volumes', ('id', '=', pool_name)):
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(pool_name))

        deps = self.dispatcher.call_sync('zfs.dataset.get_dependencies', id)
        ds = self.dispatcher.call_sync('volume.dataset.query', [('id', '=', id)], {'single': True})
        if not ds:
            raise TaskException(errno.ENOENT, 'Dataset {0} not found', id)

        for i in deps:
            if i['type'] == 'FILESYSTEM':
                self.run_subtask_sync('zfs.umount', i['id'])

            self.run_subtask_sync('zfs.destroy', i['id'])

        try:
            if ds['type'] == 'FILESYSTEM':
                self.run_subtask_sync('zfs.umount', id)

            self.run_subtask_sync('zfs.destroy', id)
        except RpcException as err:
            if err.code == errno.EBUSY and ds['type'] == 'FILESYSTEM':
                # Find out what's holding unmount or destroy
                files = list(self.dispatcher.call_sync('filesystem.get_open_files', ds['mountpoint']))

                if len(files) == 1:
                    raise TaskException(
                        errno.EBUSY,
                        'Dataset is in use by {process_name} (pid {pid}, path {path})'.format(**files[0]),
                        extra=files
                    )
                else:
                    raise TaskException(
                        errno.EBUSY,
                        'Dataset is in use by {0} processes'.format(len(files)),
                        extra=files
                    )
            else:
                raise


@description("Configures/Updates an existing Dataset's properties")
@accepts(str, h.ref('VolumeDataset'), bool)
class DatasetConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return "Configuring a dataset"

    def describe(self, id, updated_params, reset_permissions=False):
        return TaskDescription("Configuring the dataset {name}", name=id)

    def verify(self, id, updated_params, reset_permissions=False):
        pool_name, _ = split_dataset(id)
        return [f'volume:{pool_name}']

    def switch_to_acl(self, path):
        fs_path = self.dispatcher.call_sync('volume.get_dataset_path', path)
        self.join_subtasks(
            self.run_subtask('zfs.update', path, {
                'aclmode': {'value': 'discard_chmod'},
                'org.freenas:permissions_type': {'value': 'ACL'}
            }),
            self.run_subtask('file.set_permissions', fs_path, {
                'acl': DEFAULT_ACLS
            }, True)
        )

    def switch_to_chmod(self, path):
        self.run_subtask_sync('zfs.update', path, {
            'aclmode': {'value': 'passthrough'},
            'org.freenas:permissions_type': {'value': 'PERM'}
        })

    def run(self, id, updated_params, reset_permissions=False):
        pool_name, _, ds = id.partition('/')
        if not self.datastore.exists('volumes', ('id', '=', pool_name)):
            raise TaskException(errno.ENOENT, 'Volume {0} not found'.format(pool_name))

        pool_name, _, _ = id.partition('/')
        ds = self.dispatcher.call_sync('zfs.dataset.query', [('id', '=', id)], {'single': True})

        if not ds:
            raise TaskException(errno.ENOENT, 'Dataset {0} not found'.format(id))

        if 'id' in updated_params:
            self.run_subtask_sync('zfs.rename', ds['id'], updated_params['id'])
            ds['id'] = updated_params['id']

        if 'volsize' in updated_params:
            if ds['type'] != 'VOLUME':
                raise TaskException(errno.EINVAL, 'Cannot set volsize on non-volume dataset')

            if updated_params['volsize'] < q.get(ds, 'properties.volsize.parsed'):
                raise TaskException(errno.EBUSY, 'Cannot shrink a zvol')

            self.run_subtask_sync('zfs.update', ds['id'], {
                'volsize': {'value': int(updated_params['volsize'])}
            })

        if 'hidden' in updated_params:
            props = {'org.freenas:hidden': {'value': 'yes' if updated_params['hidden'] else 'no'}}
            self.run_subtask_sync('zfs.update', ds['id'], props)

        if 'metadata' in updated_params:
            props = {name: {'value': value} for name, value in updated_params['metadata'].items()}
            self.run_subtask_sync('zfs.update', ds['id'], props)

        if 'properties' in updated_params:
            props = exclude(
                updated_params['properties'],
                'used', 'usedbydataset', 'usedbysnapshots', 'usedbychildren', 'logicalused',
                'logicalreferenced', 'origin', 'written', 'usedbyrefreservation', 'referenced', 'available',
                'casesensitivity', 'compressratio', 'refcompressratio'
            )
            self.run_subtask_sync('zfs.update', ds['id'], props)

        if 'permissions_type' in updated_params:
            oldtyp = q.get(ds, 'properties.org\\.freenas:permissions_type.value')
            typ = updated_params['permissions_type']

            if oldtyp != 'ACL' and typ == 'ACL':
                self.switch_to_acl(ds['id'])

            if oldtyp != 'PERM' and typ == 'PERM':
                self.switch_to_chmod(ds['id'])

        if 'permissions' in updated_params:
            fs_path = os.path.join(VOLUMES_ROOT, ds['id'])
            self.run_subtask_sync(
                'file.set_permissions',
                fs_path,
                updated_params['permissions'],
                reset_permissions
            )

        if 'mounted' in updated_params:
            if updated_params['mounted']:
                self.run_subtask_sync('zfs.mount', ds['id'])
            else:
                self.run_subtask_sync('zfs.umount', ds['id'])


@description("Mounts target readonly dataset")
@accepts(str, str)
class DatasetTemporaryMountTask(Task):
    @classmethod
    def early_describe(cls):
        return "Mounting a dataset"

    def describe(self, id, dest):
        return TaskDescription("Mounting the dataset {name}", name=id)

    def verify(self, id, dest):
        try:
            return ['volume:{0}'.format(self.dispatcher.call_sync('volume.decode_path', id)[0])]
        except RpcException:
            return ['system']

    def run(self, id, dest):
        ds_ro = list(self.dispatcher.call_sync(
            'zfs.dataset.query',
            [('id', '=', id)],
            {'select': 'properties.readonly.rawvalue'}
        ))
        if not ds_ro:
            raise TaskException(errno.ENOENT, 'Dataset {0} does not exist'.format(id))
        if not ds_ro[0]:
            raise TaskException(errno.EINVAL, 'Only readonly datasets can have temporary mountpoints')

        try:
            bsd.nmount(source=id, fspath=dest, fstype='zfs')
        except FileNotFoundError:
            raise TaskException(errno.EACCES, 'Location {0} does not exist'.format(dest))
        except OSError:
            raise TaskException(errno.EACCES, 'Cannot mount {0} under {1}'.format(id, dest))


@description("Unmounts target readonly dataset")
@accepts(str)
class DatasetTemporaryUmountTask(Task):
    @classmethod
    def early_describe(cls):
        return "Unmounting a dataset"

    def describe(self, id):
        return TaskDescription("Unmounting the dataset {name}", name=id)

    def verify(self, id):
        try:
            return ['volume:{0}'.format(self.dispatcher.call_sync('volume.decode_path', id)[0])]
        except RpcException:
            return ['system']

    def run(self, id):
        ds_ro = list(self.dispatcher.call_sync(
            'zfs.dataset.query',
            [('id', '=', id)],
            {'select': 'properties.readonly.rawvalue'}
        ))
        if not ds_ro:
            raise TaskException(errno.ENOENT, 'Dataset {0} does not exist'.format(id))
        if not ds_ro[0]:
            raise TaskException(errno.EINVAL, 'Only readonly datasets can be unmounted')

        self.run_subtask_sync('zfs.umount', id)


@description("Creates a snapshot")
@accepts(
    h.all_of(
        h.ref('VolumeSnapshot'),
        h.any_of(
            h.required('dataset'),
            h.required('id')
        )
    ),
    bool
)
class SnapshotCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating a snapshot"

    def describe(self, snapshot, recursive=False):
        name = snapshot.get('id') or '{0}@{1}'.format(snapshot.get('dataset'), snapshot.get('name'))
        return TaskDescription("Creating the snapshot {name}", name=name)

    def verify(self, snapshot, recursive=False):
        dataset = snapshot.get('dataset') or snapshot.get('id').split('@')[0]
        return [f'zfs:{dataset}']

    def run(self, snapshot, recursive=False):
        normalize(snapshot, {
            'replicable': True,
            'lifetime': None,
            'hidden': False,
            'metadata': {}
        })

        props = {name: {'value': value} for name, value in snapshot['metadata'].items()}
        props.update({
            'org.freenas:replicable': {'value': 'yes' if snapshot['replicable'] else 'no'},
            'org.freenas:hidden': {'value': 'yes' if snapshot['hidden'] else 'no'},
            'org.freenas:lifetime': {'value': str(snapshot['lifetime'] or 'no')},
            'org.freenas:uuid': {'value': str(uuid.uuid4())}
        })

        if snapshot.get('id'):
            dataset, name = snapshot['id'].split('@')
        else:
            dataset = snapshot['dataset']
            name = snapshot.get('name', self.dispatcher.call_sync('volume.snapshot.get_snapshot_name', dataset))
            snapshot['id'] = '@'.join([dataset, name])

        self.run_subtask_sync(
            'zfs.create_snapshot',
            dataset,
            name,
            recursive,
            props
        )

        wait_for_cache(self.dispatcher, 'volume.snapshot', 'create', snapshot['id'])
        return snapshot['id']


@description("Deletes the specified snapshot")
@accepts(str, bool)
class SnapshotDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting a snapshot"

    def describe(self, id, recursive=False):
        return TaskDescription("Deleting the snapshot {name}", name=id)

    def verify(self, id, recursive=False):
        pool, ds, snap = split_snapshot_name(id)
        return [f'zfs:{ds}']

    def run(self, id, recursive=False):
        pool, ds, snap = split_snapshot_name(id)
        self.run_subtask_sync(
            'zfs.delete_snapshot',
            ds,
            snap,
            recursive
        )


@description("Updates configuration of specified snapshot")
@accepts(str, h.all_of(
    h.ref('VolumeSnapshot')
))
class SnapshotConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return "Configuring a snapshot"

    def describe(self, id, updated_params):
        return TaskDescription("Configuring the snapshot {name}", name=id)

    def verify(self, id, updated_params):
        pool, ds, snap = split_snapshot_name(id)
        return [f'zfs:{ds}']

    def run(self, id, updated_params):
        pool, ds, snap = split_snapshot_name(id)
        params = {}

        if 'id' in updated_params:
            self.run_subtask_sync('zfs.rename', id, updated_params['id'])
            id = updated_params['id']

        if 'name' in updated_params:
            new_id = '{0}@{1}'.format(ds, updated_params['name'])
            self.run_subtask_sync('zfs.rename', id, new_id)
            id = new_id

        if 'metadata' in updated_params:
            for name, value in updated_params['metadata'].items():
                params[name] = {'value': value}

        if 'lifetime' in updated_params:
            params['org.freenas:lifetime'] = {'value': str(updated_params['lifetime'] or 'no')}

        if 'replicable' in updated_params:
            params['org.freenas:replicable'] = {'value': 'yes' if updated_params['replicable'] else 'no'}

        if 'hidden' in updated_params:
            params['org.freenas:hidden'] = {'value': 'yes' if updated_params['hidden'] else 'no'}

        self.run_subtask_sync('zfs.update', id, params)


@description("Cloning the specified snapshot into new name")
@accepts(str, str)
class SnapshotCloneTask(Task):
    @classmethod
    def early_describe(cls):
        return "Cloning a snapshot"

    def describe(self, name, new_name):
        return TaskDescription("Cloning the snapshot {name}", name=name)

    def verify(self, name, new_name):
        pool, ds, snap = split_snapshot_name(name)
        return [f'zfs:{ds}']

    def run(self, name, new_name):
        self.dispatcher.exec_and_wait_for_event(
            'volume.dataset.changed',
            lambda args: args['operation'] == 'create' and new_name in args['ids'],
            lambda: self.run_subtask_sync('zfs.clone', name, new_name),
            600
        )

        type = self.dispatcher.call_sync(
            'volume.dataset.query',
            [('id', '=', new_name)],
            {'select': 'type', 'single': True}
        )
        if type == 'FILESYSTEM':
            self.run_subtask_sync('zfs.mount', new_name)


@description("Returns filesystem to the specified snapshot state")
@accepts(str, bool)
class SnapshotRollbackTask(Task):
    @classmethod
    def early_describe(cls):
        return "Returning filesystem to a snapshot state"

    def describe(self, name, force=False):
        return TaskDescription("Returning filesystem to the snapshot {name}", name=name)

    def verify(self, name, force=False):
        pool, ds, snap = split_snapshot_name(name)
        return [f'zfs:{ds}']

    def run(self, name, force=False):
        self.run_subtask_sync(
            'zfs.rollback',
            name,
            force
        )


def disk_spec_to_path(dispatcher, ident):
    return dispatcher.call_sync(
        'disk.query',
        [
            ('or', [('path', '=', ident), ('name', '=', ident), ('id', '=', ident)]),
            ('online', '=', True)
        ],
        {'single': True, 'select': 'path'}
    )


def disk_spec_to_id(dispatcher, ident):
    return dispatcher.call_sync(
        'disk.query',
        [
            ('or', [('path', '=', ident), ('name', '=', ident), ('id', '=', ident)]),
            ('online', '=', True)
        ],
        {'single': True, 'select': 'id'}
    )


def get_disk_gptid(dispatcher, disk):
    id = dispatcher.call_sync('disk.path_to_id', disk)
    config = dispatcher.call_sync('disk.get_disk_config_by_id', id)
    return config.get('data_partition_path', disk)


def convert_topology_to_gptids(dispatcher, topology):
    topology = copy.deepcopy(topology)
    for vdev, _ in iterate_vdevs(topology):
        vdev['path'] = get_disk_gptid(dispatcher, vdev['path'])

    return topology


def get_digest(password, salt=None):
    if salt is None:
        salt = base64.b64encode(os.urandom(256)).decode('utf-8')

    hmac = hashlib.pbkdf2_hmac('sha256', bytes(str(unpassword(password)), 'utf-8'), salt.encode('utf-8'), 200000)
    digest = base64.b64encode(hmac).decode('utf-8')
    return salt, digest


def is_password(password, salt, digest):
    return get_digest(password, salt)[1] == digest


def fernet_encrypt(password, in_data):
    digest = get_digest(password, '')[1]
    f = Fernet(digest)
    return f.encrypt(in_data)


def fernet_decrypt(password, in_data):
    digest = get_digest(password, '')[1]
    f = Fernet(digest)
    return f.decrypt(in_data)


def wait_for_cache(dispatcher, type, op, id):
    dispatcher.test_or_wait_for_event(
        '{0}.changed'.format(type),
        lambda args: args['operation'] == op and id in args['ids'],
        lambda: dispatcher.call_sync('{0}.query'.format(type), [('id', '=', id)], {'single': True}),
        300
    )


def simplify_topology(topology):
    def simplify_vdev(v):
        for prop in list(v):
            if prop not in ('type', 'path', 'children', 'disk_id'):
                del v[prop]

    for name, grp in topology.items():
        for vdev in grp:
            simplify_vdev(vdev)

            if 'children' in vdev:
                for child in vdev['children']:
                    simplify_vdev(child)


def convert_properties(properties):
    metadata = {}
    for name, prop in properties.items():
        if ':' in name:
            metadata[name] = prop['value']

    return metadata


def register_property_schemas(plugin):
    VOLUME_PROPERTIES = {
        'size': {
            'type': 'integer',
            'readOnly': True
        },
        'capacity': {
            'type': 'integer',
            'readOnly': True
        },
        'health': {
            'type': 'string',
            'enum': ['ONLINE', 'DEGRADED', 'FAULTED', 'OFFLINE', 'REMOVED', 'UNAVAIL', 'LOCKED']
        },
        'version': {
            'type': ['integer', 'null'],
            'readOnly': True
        },
        'delegation': {
            'type': 'boolean'
        },
        'failmode': {
            'type': 'string',
            'enum': ['wait', 'continue', 'panic'],
        },
        'autoreplace': {
            'type': 'boolean'
        },
        'dedupratio': {
            'type': 'string',
            'readOnly': True
        },
        'free': {
            'type': 'integer',
            'readOnly': True
        },
        'allocated': {
            'type': 'integer',
            'readOnly': True
        },
        'readonly': {
            'type': 'boolean'
        },
        'comment': {
            'type': 'string'
        },
        'expandsize': {
            'type': 'integer',
            'readOnly': True
        },
        'fragmentation': {
            'type': 'string',
            'readOnly': True
        },
        'leaked': {
            'type': 'integer',
            'readOnly': True
        }
    }

    DATASET_PROPERTIES = {
        'used': {
            'type': 'integer',
            'readOnly': True
        },
        'available': {
            'type': 'integer',
            'readOnly': True
        },
        'compression': {
            'type': ['string', 'null'],
            'enum': [
                'on', 'off', 'lzjb', 'zle', 'lz4', 'gzip', 'gzip-1', 'gzip-2', 'gzip-3',
                'gzip-4', 'gzip-5', 'gzip-6', 'gzip-7', 'gzip-8', 'gzip-9', None
            ]
        },
        'atime': {
            'type': ['boolean', 'null']
        },
        'dedup': {
            'type': ['string', 'null'],
            'enum': [
                'on', 'off', 'verify', None
            ]
        },
        'quota': {
            'type': ['integer', 'null']
        },
        'refquota': {
            'type': ['integer', 'null'],
        },
        'reservation': {
            'type': ['integer', 'null'],
        },
        'refreservation': {
            'type': ['integer', 'null'],
        },
        'recordsize': {
            'type': 'integer',
        },
        'casesensitivity': {
            'type': ['string', 'null'],
            'enum': ['sensitive', 'insensitive', 'mixed', None]
        },
        'volsize': {
            'type': 'integer',
            'readOnly': True
        },
        'volblocksize': {
            'type': 'integer',
            'enum': [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072]
        },
        'refcompressratio': {
            'type': 'string',
            'readOnly': True
        },
        'numclones': {
            'type': 'string',
            'readOnly': True
        },
        'compressratio': {
            'type': 'string',
            'readOnly': True
        },
        'written': {
            'type': 'integer',
            'readOnly': True
        },
        'referenced': {
            'type': 'integer',
            'readOnly': True
        },
        'readonly': {
            'type': 'boolean',
            'readOnly': True
        },
        'usedbyrefreservation': {
            'type': 'integer',
            'readOnly': True
        },
        'usedbysnapshots': {
            'type': 'integer',
            'readOnly': True
        },
        'usedbydataset': {
            'type': 'integer',
            'readOnly': True
        },
        'usedbychildren': {
            'type': 'integer',
            'readOnly': True
        },
        'logicalused': {
            'type': 'integer',
            'readOnly': True
        },
        'logicalreferenced': {
            'type': 'integer',
            'readOnly': True
        },
        'origin': {
            'type': 'string',
            'readOnly': True
        }
    }

    SNAPSHOT_PROPERTIES = {
        'used': {
            'type': 'integer',
            'readOnly': True
        },
        'referenced': {
            'type': 'integer',
            'readOnly': True
        },
        'compressratio': {
            'type': 'string',
            'readOnly': True
        },
        'clones': {
            'type': 'integer',
            'readOnly': True
        },
        'creation': {
            'type': 'datetime',
            'readOnly': True
        }
    }

    for i, props in {
        'Volume': VOLUME_PROPERTIES,
        'VolumeDataset': DATASET_PROPERTIES,
        'VolumeSnapshot': SNAPSHOT_PROPERTIES
    }.items():
        for name, prop in props.items():
            plugin.register_schema_definition('{0}Property{1}Value'.format(i, name), prop)
            plugin.register_schema_definition('{0}Property{1}'.format(i, name), {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'source': {'$ref': 'VolumePropertySource'},
                    'rawvalue': {'type': 'string', 'readOnly': True},
                    'value': {'type': ['string', 'null']},
                    'parsed': {'$ref': '{0}Property{1}Value'.format(i, name)}
                }
            })

        plugin.register_schema_definition('{0}Properties'.format(i), {
            'type': 'object',
            'additionalProperties': False,
            'properties': {name: {'$ref': '{0}Property{1}'.format(i, name)} for name in props},
        })


def collect_debug(dispatcher):
    yield AttachRPC('volume-query', 'volume.query')
    yield AttachData('volumes', dumps(list(dispatcher.datastore.query('volumes')), indent=4))


def _depends():
    return ['DevdPlugin', 'ZfsPlugin', 'AlertPlugin', 'DiskPlugin']


def _init(dispatcher, plugin):
    boot_pool = dispatcher.call_sync('zfs.pool.get_boot_pool')

    def convert_snapshot(snapshot):
        dataset, _, name = snapshot['name'].partition('@')
        pool = dataset.partition('/')[0]
        lifetime = None

        if pool == boot_pool['id']:
            return None

        try:
            lifetime = int(q.get(snapshot, 'properties.org\\.freenas:lifetime.value'))
        except (ValueError, TypeError):
            pass

        creation = int(q.get(snapshot, 'properties.creation.rawvalue', 0))
        return {
            'id': snapshot['name'],
            'volume': pool,
            'dataset': dataset,
            'name': name,
            'lifetime': lifetime,
            'expires_at': datetime.utcfromtimestamp(creation + lifetime) if lifetime else None,
            'replicable': yesno_to_bool(q.get(snapshot, 'properties.org\\.freenas:replicable.value')),
            'hidden': yesno_to_bool(q.get(snapshot, 'properties.org\\.freenas:hidden.value')),
            'properties': include(
                snapshot['properties'],
                'used', 'referenced', 'compressratio', 'clones', 'creation'
            ),
            'holds': snapshot['holds'],
            'metadata': convert_properties(snapshot['properties'])
        }

    def convert_dataset(ds):
        perms = None
        last_replicated_at = None
        last_replicated_by = None
        local_mountpoint = q.get(ds, 'properties.mountpoint.source') != 'INHERITED'

        if ds['pool'] == boot_pool['id']:
            return None

        if ds['mountpoint']:
            try:
                perms = dispatcher.call_sync('filesystem.stat', ds['mountpoint'])
            except RpcException:
                pass

        temp_mountpoint = None
        if q.get(ds, 'properties.readonly.parsed') and q.get(ds, 'properties.mounted.parsed'):
            for mnt in bsd.getmntinfo():
                if mnt.source == ds['name'] and mnt.dest != q.get(ds, 'properties.mountpoint.parsed'):
                    temp_mountpoint = mnt.dest
                    break

        if ds['mountpoint'] and '.system' not in ds['name'] and ds['name'] != ds['pool'] and local_mountpoint:
            # Correct mountpoint of a non-root dataset
            try:
                dispatcher.call_sync('zfs.dataset.inherit_property', ds['name'], 'mountpoint')
            except RpcException as err:
                logger.warning(f'Failed to fix mountpoint on dataset {ds["name"]}: {err}')

        if ds['name'] == ds['pool']:
            # Correct mountpoint of a root dataset
            desired_mountpoint = os.path.join(VOLUMES_ROOT, ds['pool'])
            if q.get(ds, 'properties.mountpoint.parsed') != desired_mountpoint:
                try:
                    dispatcher.call_sync('zfs.dataset.set_property', ds['name'], 'mountpoint', desired_mountpoint)
                except RpcException as err:
                    logger.warning(f'Failed fix mountpoint dataset {ds["name"]}: {err}')

        prop = q.get(ds, 'properties.org\\.freenas:last_replicated_at')
        if prop and prop['source'] == 'LOCAL':
            try:
                last_replicated_at = datetime.utcfromtimestamp(int(prop['value']))
            except ValueError:
                pass

        prop = q.get(ds, 'properties.org\\.freenas:last_replicated_by')
        if prop and prop['source'] == 'LOCAL':
            last_replicated_by = prop['value']

        perm_type = q.get(ds, 'properties.org\\.freenas:permissions_type')
        if ds['type'] == 'FILESYSTEM' and q.get(perm_type, 'source') != 'LOCAL':
            aclmode = q.get(ds, 'properties.aclmode.parsed')
            try:
                dispatcher.call_sync(
                    'zfs.dataset.set_property',
                    ds['name'],
                    'org.freenas:permissions_type',
                    'ACL' if aclmode in ('restricted', 'discard_chmod') else 'PERM'
                )
            except RpcException as err:
                logger.warning(f'Failed to set permissions type on dataset {ds["name"]}: {err}')

        return {
            'id': ds['name'],
            'name': ds['name'],
            'rname': 'zfs:{0}'.format(ds['id']),
            'volume': ds['pool'],
            'type': ds['type'],
            'mountpoint': q.get(ds, 'properties.mountpoint.value'),
            'temp_mountpoint': temp_mountpoint,
            'mounted': q.get(ds, 'properties.mounted.parsed'),
            'volsize': q.get(ds, 'properties.volsize.parsed'),
            'properties': include(
                ds['properties'],
                'used', 'available', 'compression', 'atime', 'dedup',
                'quota', 'refquota', 'reservation', 'refreservation',
                'casesensitivity', 'volsize', 'volblocksize', 'refcompressratio',
                'numclones', 'compressratio', 'written', 'referenced',
                'usedbyrefreservation', 'usedbysnapshots', 'usedbydataset',
                'usedbychildren', 'logicalused', 'logicalreferenced', 'origin',
                'readonly', 'recordsize'
            ),
            'permissions_type': q.get(ds, 'properties.org\\.freenas:permissions_type.value'),
            'permissions': perms['permissions'] if perms else None,
            'last_replicated_by': last_replicated_by,
            'last_replicated_at': last_replicated_at,
            'hidden': yesno_to_bool(q.get(ds, 'properties.org\\.freenas:hidden.value')),
            'metadata': convert_properties(ds['properties'])
        }

    @sync
    def on_pool_change(args):
        if args['operation'] == 'delete':
            for i in args['ids']:
                with dispatcher.get_lock('volumes'):
                    volume = dispatcher.call_sync('volume.query', [('id', '=', i)], {'single': True})
                    if volume:
                        if volume.get('key_encrypted') or volume.get('password_encrypted'):
                            continue

                        logger.info('Volume {0} is going away'.format(volume['id']))
                        dispatcher.datastore.delete('volumes', volume['id'])
                        dispatcher.dispatch_event('volume.changed', {
                            'operation': 'delete',
                            'ids': [volume['id']]
                        })

        if args['operation'] in ('create', 'update'):
            entities = filter(lambda i: i['guid'] != boot_pool['guid'], args['entities'])
            for i in entities:
                if args['operation'] == 'update':
                    volume = dispatcher.datastore.get_one('volumes', ('id', '=', i['name']))
                    if volume:
                        dispatcher.dispatch_event('volume.changed', {
                            'operation': 'update',
                            'ids': [volume['id']]
                        })
                    continue

                with dispatcher.get_lock('volumes'):
                    try:
                        dispatcher.datastore.insert('volumes', {
                            'id': i['name'],
                            'guid': str(i['guid']),
                            'type': 'zfs',
                            'attributes': {},
                            'key_encrypted': False,
                            'password_encrypted': False,
                            'encryption': {
                                'key': None,
                                'hashed_password': None,
                                'salt': None,
                                'slot': None
                            },
                            'auto_unlock': False
                        })
                    except DuplicateKeyException:
                        # already inserted by task
                        dispatcher.dispatch_event('volume.changed', {
                            'operation': 'create',
                            'ids': [i['name']]
                        })
                        continue

                    logger.info('New volume {0} <{1}>'.format(i['name'], i['guid']))

                    # Set correct mountpoint
                    dispatcher.call_sync(
                        'zfs.dataset.set_property',
                        i['name'],
                        'mountpoint',
                        os.path.join(VOLUMES_ROOT, i['name'])
                    )

                    if q.get(i, 'properties.altroot.source') != 'DEFAULT':
                        # Ouch. That pool is created or imported with altroot.
                        # We need to export and reimport it to remove altroot property
                        dispatcher.call_task_sync('zfs.pool.export', i['name'])
                        dispatcher.call_task_sync('zfs.pool.import', i['guid'], i['name'])

                    dispatcher.dispatch_event('volume.changed', {
                        'operation': 'create',
                        'ids': [i['name']]
                    })

    @sync
    def on_snapshot_change(args):
        snapshots.propagate(args, callback=convert_snapshot)

    @sync
    def on_dataset_change(args):
        datasets.propagate(args, callback=convert_dataset)

    @sync
    def on_vdev_state_change(args):
        guid = args['guid']
        volume = dispatcher.call_sync('volume.query', [('guid', '=', guid)], {'single': True})
        if not volume:
            return

        if volume['status'] in ('UNKNOWN', 'LOCKED'):
            return

        if args['vdev_guid'] == guid:
            # Ignore root vdev state changes
            return

        vdev = vdev_by_guid(volume['topology'], args['vdev_guid'])
        if not vdev:
            return

        if args['status'] in ('FAULTED', 'REMOVED'):
            logger.warning('Vdev {0} of pool {1} is now in {2} state - attempting to replace'.format(
                args['vdev_guid'],
                volume['id'],
                args['status']
            ))

            dispatcher.submit_task('volume.autoreplace', volume['id'], args['vdev_guid'])

    @sync
    def on_disk_attached(args):
        for vol in dispatcher.call_sync('volume.query', [('status', '=', 'UNKNOWN')]):
            if vol.get('key_encrypted') or vol.get('password_encrypted'):
                continue

            for vdev, group in iterate_vdevs(vol['topology']):
                if group != 'data':
                    continue

                if vdev['type'] == 'disk' and vdev['disk_id'] == args['id']:
                    pool = first_or_default(None, dispatcher.call_sync('zfs.pool.find', vol['id']))
                    if pool and pool['status'] != 'UNAVAIL':
                        dispatcher.call_task_sync('zfs.pool.import', vol['guid'])
                        dispatcher.call_task_sync('zfs.mount', vol['id'], True)

    def on_server_ready(args):
        for vol in dispatcher.call_sync('volume.query'):
            if vol.get('providers_presence', 'ALL') == 'NONE':
                if vol.get('auto_unlock') and vol.get('key_encrypted') and not vol.get('password_encrypted'):
                    dispatcher.call_task_sync('volume.unlock', vol['id'])

    def scrub_snapshots():
        interval = dispatcher.configstore.get('middleware.snapshot_scrub_interval')
        while True:
            gevent.sleep(interval)
            ts = datetime.utcnow()
            for snap in dispatcher.call_sync('volume.snapshot.query', [('expires_at', '<=', ts)], no_copy=True):
                dispatcher.call_task_sync('volume.snapshot.delete', snap['id'])

    plugin.register_schema_definition('Volume', {
        'type': 'object',
        'title': 'volume',
        'additionalProperties': False,
        'readOnly': True,
        'properties': {
            'id': {'type': 'string'},
            'guid': {
                'type': 'string',
                'readOnly': True
            },
            'type': {
                'type': 'string',
                'enum': ['zfs']
            },
            'rname': {'type': 'string'},
            'disks': {
                'type': 'array',
                'items': {'$type': 'string'}
            },
            'topology': {'$ref': 'ZfsTopology'},
            'scan': {'$ref': 'ZfsScan'},
            'mountpoint': {
                'type': ['string', 'null'],
                'readOnly': True
            },
            'status': {'$ref': 'VolumeStatus'},
            'upgraded': {
                'oneOf': [
                    {'type': 'boolean'},
                    {'type': 'null'}
                ],
                'readOnly': True
            },
            'key_encrypted': {'type': 'boolean'},
            'password_encrypted': {'type': 'boolean'},
            'encryption': {'$ref': 'VolumeEncryption'},
            'auto_unlock': {
                'oneOf': [
                    {'type': 'boolean'},
                    {'type': 'null'}
                ]
            },
            'providers_presence': {
                'oneOf': [
                    {'$ref': 'VolumeProvidersPresence'},
                    {'type': 'null'}
                ],
                'readOnly': True
            },
            'properties': {'$ref': 'VolumeProperties', 'readOnly': True},
            'attributes': {'type': 'object'},
            'params': {
                'type': ['object', 'null'],
                'properties': {
                    'mount': {'type': 'boolean'},
                    'mountpoint': {'type': 'string'},
                    'blocksize': {'type': 'number'},
                    'swapsize': {'type': 'number'}
                }
            }
        }
    })

    plugin.register_schema_definition('VolumeStatus', {
        'type': 'string',
        'readOnly': True,
        'enum': ['UNAVAIL', 'UNKNOWN', 'LOCKED', 'DEGRADED', 'ONLINE']
    })

    plugin.register_schema_definition('VolumeProvidersPresence', {
        'type': 'string',
        'enum': ['ALL', 'PART', 'NONE']
    })

    plugin.register_schema_definition('VolumePropertySource', {
        'type': 'string',
        'enum': ['NONE', 'DEFAULT', 'LOCAL', 'INHERITED', 'RECEIVED']
    })

    plugin.register_schema_definition('VolumeEncryption', {
        'type': 'object',
        'readOnly': True,
        'properties': {
            'key': {'type': ['string', 'null']},
            'hashed_password': {'type': ['string', 'null']},
            'salt': {'type': ['string', 'null']},
            'slot': {'type': ['integer', 'null']}
        }
    })

    plugin.register_schema_definition('VolumeDataset', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'rname': {'type': 'string'},
            'volume': {'type': 'string'},
            'mountpoint': {
                'type': ['string', 'null'],
                'readOnly': True
            },
            'temp_mountpoint': {
                'type': ['string', 'null'],
                'readOnly': True
            },
            'mounted': {'type': 'boolean'},
            'type': {'allOf': [
                {'$ref': 'VolumeDatasetType'},
                {'readOnly': True}
            ]},
            'volsize': {'type': ['integer', 'null']},
            'properties': {'$ref': 'VolumeDatasetProperties'},
            'permissions': {'$ref': 'Permissions'},
            'permissions_type': {'$ref': 'VolumeDatasetPermissionsType'},
            'last_replicated_by': {'type': ['string', 'null']},
            'last_replicated_at': {'type': ['datetime', 'null']},
            'hidden': {'type': 'boolean'},
            'metadata': {
                'type': 'object',
                'additionalProperties': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('VolumeDatasetType', {
        'type': 'string',
        'enum': ['FILESYSTEM', 'VOLUME'],
    })

    plugin.register_schema_definition('VolumeDatasetPermissionsType', {
        'type': 'string',
        'enum': ['PERM', 'ACL']
    })

    plugin.register_schema_definition('VolumeSnapshot', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'volume': {'type': 'string'},
            'dataset': {'type': 'string'},
            'name': {'type': 'string'},
            'replicable': {'type': 'boolean'},
            'hidden': {'type': 'boolean'},
            'lifetime': {'type': ['integer', 'null']},
            'expires_at': {'type': ['datetime', 'null']},
            'properties': {'$ref': 'VolumeSnapshotProperties'},
            'holds': {'type': 'object'},
            'metadata': {
                'type': 'object',
                'additionalProperties': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('VolumeDiskLabel', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'volume_id': {'type': 'string'},
            'volume_guid': {'type': 'string'},
            'vdev_guid': {'type': 'string'},
            'hostname': {'type': 'string'},
            'hostid': {'type': ['integer', 'null']}
        }
    })

    plugin.register_schema_definition('DisksAllocation', {
        'type': 'object',
        'additionalProperties': {
            'type': 'object',
            'additionalProperties': False,
            'properties': {
                'type': {'$ref': 'DisksAllocationType'},
                'name': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('DisksAllocationType', {
        'type': 'string',
        'enum': ['BOOT', 'VOLUME', 'EXPORTED_VOLUME', 'ISCSI'],
    })

    plugin.register_schema_definition('ImportableDisk', {
        'type': 'object',
        'properties': {
            'path': {'type': 'string'},
            'fstype': {'type': 'string'},
            'size': {'type': 'integer'},
            'label': {'type': ['string', 'null']}
        }
    })

    plugin.register_schema_definition('VolumeImportParams', {
        'type': 'object',
        'properties': {
            'key': {'type': ['string', 'null']},
            'key_fd': {'type': ['fd', 'null']},
            'auto_unlock': {'type': 'boolean'},
            'disks': {
                'type': 'array',
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('VolumeVdevRecommendation', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'drives': {'type': 'integer'},
            'type': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('VolumeVdevRecommendations', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'storage': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'storage': {'$ref': 'VolumeVdevRecommendation'},
                    'redundancy': {'$ref': 'VolumeVdevRecommendation'},
                    'speed': {'$ref': 'VolumeVdevRecommendation'},
                }
            },
            'redundancy': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'storage': {'$ref': 'VolumeVdevRecommendation'},
                    'redundancy': {'$ref': 'VolumeVdevRecommendation'},
                    'speed': {'$ref': 'VolumeVdevRecommendation'},
                }
            },
            'speed': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'storage': {'$ref': 'VolumeVdevRecommendation'},
                    'redundancy': {'$ref': 'VolumeVdevRecommendation'},
                    'speed': {'$ref': 'VolumeVdevRecommendation'},
                }
            },
        }
    })

    register_property_schemas(plugin)

    plugin.register_provider('volume', VolumeProvider)
    plugin.register_provider('volume.dataset', DatasetProvider)
    plugin.register_provider('volume.snapshot', SnapshotProvider)
    plugin.register_task_handler('volume.create', VolumeCreateTask)
    plugin.register_task_handler('volume.create_auto', VolumeAutoCreateTask)
    plugin.register_task_handler('volume.delete', VolumeDestroyTask)
    plugin.register_task_handler('volume.delete_exported', ExportedVolumeDestroyTask)
    plugin.register_task_handler('volume.import', VolumeImportTask)
    plugin.register_task_handler('volume.import_disk', VolumeDiskImportTask)
    plugin.register_task_handler('volume.autoimport', VolumeAutoImportTask)
    plugin.register_task_handler('volume.export', VolumeDetachTask)
    plugin.register_task_handler('volume.update', VolumeUpdateTask)
    plugin.register_task_handler('volume.upgrade', VolumeUpgradeTask)
    plugin.register_task_handler('volume.autoreplace', VolumeAutoReplaceTask)
    plugin.register_task_handler('volume.lock', VolumeLockTask)
    plugin.register_task_handler('volume.unlock', VolumeUnlockTask)
    plugin.register_task_handler('volume.rekey', VolumeRekeyTask)
    plugin.register_task_handler('volume.keys.backup', VolumeBackupKeysTask)
    plugin.register_task_handler('volume.keys.backup_to_file', VolumeBackupKeysToFileTask)
    plugin.register_task_handler('volume.keys.restore', VolumeRestoreKeysTask)
    plugin.register_task_handler('volume.keys.restore_from_file', VolumeRestoreKeysFromFileTask)
    plugin.register_task_handler('volume.scrub', VolumeScrubTask)
    plugin.register_task_handler('volume.vdev.replace', VolumeReplaceTask)
    plugin.register_task_handler('volume.vdev.online', VolumeOnlineVdevTask)
    plugin.register_task_handler('volume.vdev.offline', VolumeOfflineVdevTask)
    plugin.register_task_handler('volume.dataset.create', DatasetCreateTask)
    plugin.register_task_handler('volume.dataset.delete', DatasetDeleteTask)
    plugin.register_task_handler('volume.dataset.update', DatasetConfigureTask)
    plugin.register_task_handler('volume.dataset.temporary.mount', DatasetTemporaryMountTask)
    plugin.register_task_handler('volume.dataset.temporary.umount', DatasetTemporaryUmountTask)
    plugin.register_task_handler('volume.snapshot.create', SnapshotCreateTask)
    plugin.register_task_handler('volume.snapshot.delete', SnapshotDeleteTask)
    plugin.register_task_handler('volume.snapshot.update', SnapshotConfigureTask)
    plugin.register_task_handler('volume.snapshot.clone', SnapshotCloneTask)
    plugin.register_task_handler('volume.snapshot.rollback', SnapshotRollbackTask)

    plugin.register_hook('volume.pre_destroy')
    plugin.register_hook('volume.pre_detach')
    plugin.register_hook('volume.pre_create')
    plugin.register_hook('volume.post_attach')

    plugin.register_hook('volume.pre_rename')
    plugin.register_hook('volume.post_rename')

    plugin.register_event_handler('entity-subscriber.zfs.pool.changed', on_pool_change)
    plugin.register_event_handler('zfs.pool.vdev_state_changed', on_vdev_state_change)
    plugin.register_event_handler('disk.attached', on_disk_attached)
    plugin.register_event_handler('server.ready', on_server_ready)

    plugin.register_event_type('volume.changed')
    plugin.register_event_type('volume.dataset.changed')
    plugin.register_event_type('volume.snapshot.changed')

    plugin.register_debug_hook(collect_debug)

    for pool in dispatcher.call_sync('zfs.pool.query'):
        if dispatcher.datastore.exists('volumes', ('id', '=', pool['id'])):
            continue

        if pool['guid'] == boot_pool['guid']:
            continue

        logger.info('New volume {0} <{1}>'.format(pool['name'], pool['guid']))
        dispatcher.datastore.insert('volumes', {
            'id': pool['name'],
            'guid': str(pool['guid']),
            'type': 'zfs',
            'encryption': {
                'key': None,
                'hashed_password': None,
                'salt': None,
                'slot': None
            },
            'key_encrypted': False,
            'password_encrypted': False,
            'auto_unlock': False,
            'attributes': {}
        })

    plugin.push_status('Populating volume cache...')

    global snapshots
    snapshots = EventCacheStore(dispatcher, 'volume.snapshot')
    snapshots.populate(dispatcher.call_sync('zfs.snapshot.query', no_copy=True), callback=convert_snapshot)
    snapshots.ready = True
    plugin.register_event_handler(
        'entity-subscriber.zfs.snapshot.changed',
        on_snapshot_change
    )

    global datasets
    datasets = EventCacheStore(dispatcher, 'volume.dataset')
    datasets.populate(dispatcher.call_sync('zfs.dataset.query', no_copy=True), callback=convert_dataset)
    datasets.ready = True
    plugin.register_event_handler(
        'entity-subscriber.zfs.dataset.changed',
        on_dataset_change
    )

    gevent.spawn(scrub_snapshots)
    dispatcher.track_resources(
        'volume.query',
        'entity-subscriber.volume.changed',
        lambda id: f'volume:{id}',
        lambda volume: ['root'],
        lambda volume: [f'zpool:{volume["id"]}'] if volume['status'] not in ('UNKNOWN', 'LOCKED') else []
    )
