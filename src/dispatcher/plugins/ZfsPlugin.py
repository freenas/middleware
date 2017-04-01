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
import bsd
import errno
import logging
import time
import gevent
import libzfs
from threading import Thread, Event
from cache import EventCacheStore
from event import sync
from task import (
    Provider, Task, ProgressTask, TaskWarning, TaskException,
    VerifyException, TaskAbortException, query, TaskDescription
)
from freenas.dispatcher.rpc import RpcException, accepts, returns, description, private, generator
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.dispatcher.jsonenc import dumps
from debug import AttachData, AttachCommandOutput
from lib.zfs import iterate_vdevs, vdev_by_guid, vdev_by_path, get_disks
from freenas.utils.trace_logger import TRACE
from freenas.utils import first_or_default, query as q
from utils import is_child, split_dataset


USER_CACHE_FILE = '/data/zfs/volume.cache'
VOLATILE_ZFS_PROPERTIES = [
    'used', 'available', 'referenced', 'compressratio', 'usedbysnapshots',
    'usedbydataset', 'usedbychildren', 'usedbyrefreservation', 'refcompressratio',
    'written', 'logicalused', 'logicalreferenced'
]

logger = logging.getLogger('ZfsPlugin')
pools = None
datasets = None
snapshots = None
zfs = None


@description("Provides information about ZFS pools")
class ZpoolProvider(Provider):
    @description("Lists ZFS pools")
    @query('ZfsPool')
    @generator
    def query(self, filter=None, params=None):
        return pools.query(*(filter or []), stream=True, **(params or {}))

    @accepts(h.one_of(str, None))
    @returns(h.array(h.ref('ZfsPool')))
    def find(self, name=None):
        zfs = get_zfs()
        return self.dispatcher.threaded(lambda: [
            p.__getstate__() for p in zfs.find_import(name=name, search_paths=['/dev/gptid'])
        ])

    @accepts()
    @returns(h.ref('ZfsPool'))
    def get_boot_pool(self):
        name = self.configstore.get('system.boot_pool_name')
        return pools[name]

    @accepts(str)
    @returns(h.array(str))
    def get_disks(self, name):
        pool = pools.get(name)
        if not pool:
            raise RpcException(errno.ENOENT, 'Pool {0} not found'.format(name))

        return [v['path'] for v, _ in iterate_vdevs(pool['groups'])]

    @accepts(str)
    @returns(h.object())
    def get_disk_label(self, device):
        try:
            label = libzfs.read_label(device)
            if not label:
                return None

            if label.get('state') == libzfs.PoolState.DESTROYED:
                return None

            return label
        except OSError as err:
            raise RpcException(err.errno, err.strerror)

    @returns(h.object())
    def get_capabilities(self):
        return {
            'vdev_types': {
                'disk': {
                    'min_devices': 1,
                    'max_devices': 1
                },
                'mirror': {
                    'min_devices': 2
                },
                'raidz1': {
                    'min_devices': 2
                },
                'raidz2': {
                    'min_devices': 3
                },
                'raidz3': {
                    'min_devices': 4
                },
                'spare': {
                    'min_devices': 1
                }
            },
            'vdev_groups': {
                'data': {
                    'allowed_vdevs': ['disk', 'file', 'mirror', 'raidz1', 'raidz2', 'raidz3', 'spare']
                },
                'log': {
                    'allowed_vdevs': ['disk', 'mirror']
                },
                'cache': {
                    'allowed_vdevs': ['disk']
                }
            }
        }

    @accepts(str, str)
    @returns(h.ref('ZfsVdev'))
    def vdev_by_guid(self, name, guid):
        pool = pools.get(name)
        return vdev_by_guid(pool['groups'], guid)

    @accepts(str, str)
    @returns(h.ref('ZfsVdev'))
    def vdev_by_path(self, name, path):
        pool = pools.get(name)
        return vdev_by_path(pool['groups'], path)

    @private
    def set_property(self, pool_name, property_name, value):
        def doit():
            zfs = get_zfs()
            pool = zfs.get(pool_name)
            pool.properties[property_name] = value

        self.dispatcher.threaded(doit)


@description('Provides information about ZFS datasets')
class ZfsDatasetProvider(Provider):
    @query('ZfsDataset')
    @generator
    def query(self, filter=None, params=None):
        return datasets.query(*(filter or []), stream=True, **(params or {}))

    @accepts(h.array(str))
    @returns(h.object())
    def get_properties_allowed_values(self, properties):
        accessible_properties = ['dedup', 'compression', 'atime', 'casesensitivity']
        try:
            props_allowed_values = {}
            zfs = get_zfs()
            ds = zfs.get_dataset(self.configstore.get('system.boot_pool_name'))

            for prop in properties:
                if prop in accessible_properties:
                    props_allowed_values[prop] = list(ds.properties[prop].allowed_values.split('|'))
                    # ZFS separators usage for allowed values of 'dedup' property is inconsisten,
                    # both comma and pipe symbols are used. This part makes the output list consistent
                    if prop == 'dedup':
                        for value in props_allowed_values[prop]:
                            if ', ' in value:
                                props_allowed_values[prop].remove(value)
                                props_allowed_values[prop].extend(value.split(', '))
                else:
                    props_allowed_values[prop] = ""

            return props_allowed_values
        except libzfs.ZFSException as err:
            if err.code == libzfs.Error.NOENT:
                raise RpcException(errno.ENOENT, str(err))

            raise RpcException(zfs_error_to_errno(err.code), str(err))

    @accepts(str)
    @returns(h.array(
        h.one_of(
            h.ref('ZfsDataset'),
            h.ref('ZfsSnapshot')
        )
    ))
    def get_dependencies(self, dataset_name):
        try:
            zfs = get_zfs()
            ds = zfs.get_dataset(dataset_name)
            deps = list(ds.dependents)
            return deps
        except libzfs.ZFSException as err:
            if err.code == libzfs.Error.NOENT:
                raise RpcException(errno.ENOENT, str(err))

            raise RpcException(zfs_error_to_errno(err.code), str(err))

    @accepts(str)
    @returns(h.array(h.ref('ZfsSnapshot')))
    def get_snapshots(self, dataset_name):
        try:
            zfs = get_zfs()
            ds = zfs.get_dataset(dataset_name)
            snaps = self.dispatcher.threaded(lambda: [d.__getstate__() for d in ds.snapshots])
            snaps.sort(key=lambda s: int(q.get(s, 'properties.creation.rawvalue')))
            return snaps
        except libzfs.ZFSException as err:
            if err.code == libzfs.Error.NOENT:
                raise RpcException(errno.ENOENT, str(err))

            raise RpcException(zfs_error_to_errno(err.code), str(err))

    @returns(int)
    def estimate_send_size(self, dataset_name, snapshot_name, anchor_name=None):
        try:
            zfs = get_zfs()
            ds = zfs.get_object('{0}@{1}'.format(dataset_name, snapshot_name))
            if anchor_name:
                return ds.get_send_space('{0}@{1}'.format(dataset_name, anchor_name))

            return ds.get_send_space()
        except libzfs.ZFSException as err:
            raise RpcException(zfs_error_to_errno(err.code), str(err))

    @accepts(str)
    @returns(h.ref('ZfsResumeToken'))
    def describe_resume_token(self, token):
        zfs = get_zfs()
        return zfs.describe_resume_token(token)

    @private
    def refresh_resume_tokens(self):
        zfs = get_zfs()
        changed = {}
        with self.dispatcher.get_lock('zfs-cache'):
            for key, i in datasets.itervalid():
                def doit():
                    props = i['properties']
                    prop = 'receive_resume_token'
                    ds = zfs.get_dataset(i['id'])

                    if props[prop]['rawvalue'] != ds.properties[prop].rawvalue:
                        props[prop] = ds.properties[prop].__getstate__()
                        return True

                try:
                    if self.dispatcher.threaded(doit):
                        changed[key] = i
                except libzfs.ZFSException:
                    pass

            datasets.update(**changed)

    @private
    def set_property(self, dataset_name, property_name, value):
        def doit():
            zfs = get_zfs()
            pool = zfs.get_dataset(dataset_name)
            if ':' in property_name:
                pool.properties[property_name] = libzfs.ZFSUserProperty(value)
            else:
                pool.properties[property_name].value = value

        self.dispatcher.threaded(doit)

    @private
    def inherit_property(self, dataset_name, property_name):
        def doit():
            zfs = get_zfs()
            pool = zfs.get_dataset(dataset_name)
            pool.properties[property_name].inherit()

        self.dispatcher.threaded(doit)


@description('Provides information about ZFS snapshots')
class ZfsSnapshotProvider(Provider):
    @query('ZfsSnapshot')
    @generator
    def query(self, filter=None, params=None):
        return snapshots.query(*(filter or []), stream=True, **(params or {}))


class ScanStatusTaskMixin(object):
    def start_watch(self, pool_name, scan_function):
        self.watch_event = Event()
        self.watch_thread = Thread(target=self.watch, args=(pool_name, scan_function), daemon=True)
        self.watch_thread.start()

    def stop_watch(self):
        if self.watch_thread:
            self.watch_thread.join()

    def wait_watch(self):
        if hasattr(self, 'watch_event'):
            self.watch_event.wait()

        self.stop_watch()

    def watch(self, pool_name, scan_function):
        zfs = get_zfs()
        while True:
            time.sleep(1)

            try:
                pool = zfs.get(pool_name)
                scrub = pool.scrub
            except libzfs.ZFSException as err:
                raise TaskException(zfs_error_to_errno(err.code), str(err))

            if scrub.function != scan_function:
                return

            if scrub.state == libzfs.ScanState.SCANNING:
                self.set_progress(scrub.percentage, "In progress...")
                continue

            if scrub.state == libzfs.ScanState.FINISHED:
                self.set_progress(100, "Finished")
                self.watch_event.set()
                return

            if scrub.state == libzfs.ScanState.CANCELED:
                self.watch_event.set()
                return


@private
@description("Scrubs ZFS pool")
@accepts(str, int)
class ZpoolScrubTask(ProgressTask, ScanStatusTaskMixin):
    def __init__(self, dispatcher):
        super(ZpoolScrubTask, self).__init__(dispatcher)
        self.pool = None
        self.abort_flag = False

    @classmethod
    def early_describe(cls):
        return "Scrubbing ZFS pool"

    def describe(self, pool):
        return TaskDescription("Scrubbing ZFS pool {name}", name=pool)

    def verify(self, pool, threshold=None):
        return [f'zpool:{pool}']

    def run(self, pool):
        self.pool = pool
        try:
            zfs = get_zfs()
            pool = zfs.get(self.pool)
            pool.start_scrub()
            self.start_watch(self.pool, libzfs.ScanFunction.SCRUB)
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))

        self.wait_watch()
        if self.abort_flag:
            raise TaskAbortException(errno.EINTR, "User invoked Task.abort()")

    def abort(self):
        try:
            zfs = get_zfs()
            pool = zfs.get(self.pool)
            self.abort_flag = True
            pool.stop_scrub()
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@description("Creates new ZFS pool")
@accepts(str, h.ref('ZfsTopology'), h.object())
class ZpoolCreateTask(Task):
    def __partition_to_disk(self, part):
        result = self.dispatcher.call_sync('disk.get_partition_config', part)
        return os.path.basename(result['disk_id'])

    def __get_disks(self, topology):
        result = []
        for gname, vdevs in list(topology.items()):
            for vdev in vdevs:
                if vdev['type'] == 'disk':
                    result.append(self.__partition_to_disk(vdev['path']))
                    continue

                if 'children' in vdev:
                    result += [self.__partition_to_disk(i['path']) for i in vdev['children']]

        return ['disk:{0}'.format(d) for d in result]

    @classmethod
    def early_describe(cls):
        return 'Creating ZFS pool'

    def describe(self, name, topology, params=None):
        return TaskDescription('Creating ZFS pool {name}', name=name)

    def verify(self, name, topology, params=None):
        return self.__get_disks(topology)

    def run(self, name, topology, params=None):
        params = params or {}
        zfs = get_zfs()
        if name in zfs.pools:
            raise TaskException(errno.EEXIST, 'Pool with same name already exists')

        mountpoint = params.get('mountpoint')
        fsopts = {}

        if not mountpoint:
            raise TaskException(errno.EINVAL, 'Please supply valid "mountpoint" parameter')

        for k, v in params.get('fsopts', {}).items():
            if v.get('value'):
                fsopts[k] = v['value']
                continue

            if v.get('parsed'):
                fsopts[k] = libzfs.serialize_zfs_prop(k, v['parsed'])
                continue

        opts = {
            'feature@async_destroy': 'enabled',
            'feature@empty_bpobj': 'enabled',
            'feature@lz4_compress': 'enabled',
            'feature@multi_vdev_crash_dump': 'enabled',
            'feature@spacemap_histogram': 'enabled',
            'feature@enabled_txg': 'enabled',
            'feature@hole_birth': 'enabled',
            'feature@extensible_dataset': 'enabled',
            'feature@bookmarks': 'enabled',
            'feature@filesystem_limits': 'enabled',
            'feature@embedded_data': 'enabled',
            'feature@large_blocks': 'enabled',
            'feature@sha512': 'enabled',
            'feature@skein': 'enabled',
            'cachefile': USER_CACHE_FILE,
            'failmode': 'continue',
            'autoexpand': 'on',
        }

        fsopts.update({
            'compression': 'lz4',
            'aclmode': 'passthrough',
            'aclinherit': 'passthrough',
            'mountpoint': mountpoint
        })

        nvroot = convert_topology(zfs, topology)

        try:
            self.dispatcher.exec_and_wait_for_event(
                'fs.zfs.pool.created',
                lambda args: args['pool'] == name,
                lambda: zfs.create(name, nvroot, opts, fsopts),
                600
            )
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


class ZpoolBaseTask(ProgressTask):
    def verify(self, *args, **kwargs):
        return [f'zpool:{args[0]}']


@private
@accepts(str, h.object())
@description('Updates ZFS pool configuration')
class ZpoolConfigureTask(ZpoolBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Updating ZFS pool configuration'

    def describe(self, pool, updated_props):
        return TaskDescription('Updating ZFS pool {name} configuration', name=pool)

    def run(self, pool, updated_props):
        try:
            zfs = get_zfs()
            pool = zfs.get(pool)
            for name, value in updated_props:
                prop = pool.properties[name]
                prop.value = value
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str)
@description('Destroys ZFS pool')
class ZpoolDestroyTask(ZpoolBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Destroying ZFS pool'

    def describe(self, name):
        return TaskDescription('Destroying ZFS pool {name}', name=name)

    def run(self, name):
        try:
            zfs = get_zfs()
            zfs.destroy(name)
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(
    str,
    h.any_of(
        h.ref('ZfsTopology'),
        None
    ),
    h.any_of(
        h.array(h.ref('ZfsVdevExtension')),
        None
    )
)
@description('Extends ZFS pool with a new disks')
class ZpoolExtendTask(ZpoolBaseTask, ScanStatusTaskMixin):
    @classmethod
    def early_describe(cls):
        return 'Extending ZFS pool'

    def describe(self, pool, new_vdevs, updated_vdevs):
        return TaskDescription('Extending ZFS pool {name}', name=pool)

    def run(self, pool, new_vdevs, updated_vdevs):
        try:
            zfs = get_zfs()
            pool = zfs.get(pool)

            if new_vdevs:
                nvroot = convert_topology(zfs, new_vdevs)
                pool.attach_vdevs(nvroot)

            if updated_vdevs:
                for i in updated_vdevs:
                    vdev = pool.vdev_by_guid(int(i['target_guid']))
                    if not vdev:
                        raise TaskException(errno.ENOENT, 'Vdev with GUID {0} not found'.format(i['target_guid']))

                    new_vdev = libzfs.ZFSVdev(zfs, i['vdev']['type'])
                    new_vdev.path = i['vdev']['path']
                    vdev.attach(new_vdev)

                self.start_watch(pool.name, libzfs.ScanFunction.RESILVER)
                self.wait_watch()
                self.stop_watch()
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, str)
@description('Detaches disk from ZFS pool')
class ZpoolDetachTask(ZpoolBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Detaching disk from ZFS pool'

    def describe(self, pool, guid):
        try:
            disk = self.dispatcher.call_sync('disk.query', [('id', '=', guid)], {'single': True})
        except RpcException:
            disk = None
        return TaskDescription(
            'Detaching disk {disk} from ZFS pool {name}',
            disk=disk.get('path', guid) if disk else guid,
            name=pool
        )

    def run(self, pool, guid):
        try:
            zfs = get_zfs()
            pool = zfs.get(pool)
            vdev = pool.vdev_by_guid(int(guid))
            if not vdev:
                raise TaskException(errno.ENOENT, 'Vdev with GUID {0} not found'.format(guid))

            if vdev.group == 'data' or (vdev.parent and vdev.parent.type == 'spare'):
                vdev.detach()
            else:
                vdev.remove()
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, str, h.ref('ZfsVdev'))
@description('Replaces one of ZFS pool\'s disks with a new disk')
class ZpoolReplaceTask(ZpoolBaseTask, ScanStatusTaskMixin):
    @classmethod
    def early_describe(cls):
        return 'Replacing disk in ZFS pool'

    def describe(self, pool, guid, vdev):
        try:
            disk = self.dispatcher.call_sync('disk.query', [('id', '=', guid)], {'single': True})
        except RpcException:
            disk = None
        return TaskDescription(
            'Replacing disk {disk} with disk {new_disk} in ZFS pool {name}',
            disk=disk.get('path', guid) if disk else guid,
            new_disk=vdev.get('path', '') if vdev else '',
            name=pool
        )

    def run(self, pool, guid, vdev):
        try:
            zfs = get_zfs()
            pool = zfs.get(pool)
            ovdev = pool.vdev_by_guid(int(guid))
            if not vdev:
                raise TaskException(errno.ENOENT, 'Vdev with GUID {0} not found'.format(guid))

            new_vdev = libzfs.ZFSVdev(zfs, vdev['type'])
            new_vdev.path = vdev['path']

            ovdev.replace(new_vdev)
            self.start_watch(pool.name, libzfs.ScanFunction.RESILVER)
            self.wait_watch()
            self.stop_watch()
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, str, bool)
@description('Sets disk in ZFS pool offline')
class ZpoolOfflineDiskTask(ZpoolBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Setting disk in ZFS pool offline'

    def describe(self, pool, guid, temporary=False):
        try:
            disk = self.dispatcher.call_sync('disk.query', [('id', '=', guid)], {'single': True})
        except RpcException:
            disk = None
        return TaskDescription(
            'Setting disk {disk} in ZFS pool {name} offline',
            disk=disk.get('path', guid) if disk else guid,
            name=pool
        )

    def run(self, pool, guid, temporary=False):
        try:
            zfs = get_zfs()
            pool = zfs.get(pool)
            vdev = pool.vdev_by_guid(int(guid))
            if not vdev:
                raise TaskException(errno.ENOENT, 'Vdev with GUID {0} not found'.format(guid))

            vdev.offline(temporary)
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, str)
@description('Sets disk in ZFS pool online')
class ZpoolOnlineDiskTask(ZpoolBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Setting disk in ZFS pool online'

    def describe(self, pool, guid):
        try:
            disk = self.dispatcher.call_sync('disk.query', [('id', '=', guid)], {'single': True})
        except RpcException:
            disk = None
        return TaskDescription(
            'Setting disk {disk} in ZFS pool {name} online',
            disk=disk.get('path', guid) if disk else guid,
            name=pool
        )

    def run(self, pool, guid):
        try:
            zfs = get_zfs()
            pool = zfs.get(pool)
            vdev = pool.vdev_by_guid(int(guid))
            if not vdev:
                raise TaskException(errno.ENOENT, 'Vdev with GUID {0} not found'.format(guid))

            vdev.online()
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str)
@description('Upgrades ZFS pool to latest ZFS version')
class ZpoolUpgradeTask(ZpoolBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Upgrading ZFS pool to latest ZFS version'

    def describe(self, pool):
        return TaskDescription('Upgrading ZFS pool {name} to latest ZFS version', name=pool)

    def run(self, pool):
        try:
            zfs = get_zfs()
            pool = zfs.get(pool)
            pool.upgrade()
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, str, h.object())
@description('Imports detached ZFS pool')
class ZpoolImportTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Importing ZFS pool'

    def describe(self, guid, name=None, properties=None):
        return TaskDescription('Importing ZFS pool {name}', name=name or '')

    def verify(self, guid, name=None, properties=None):
        zfs = get_zfs()

        if guid.isdigit():
            pool = first_or_default(
                lambda p: str(p['guid']) == guid,
                self.dispatcher.threaded(
                    lambda: [p.__getstate__() for p in zfs.find_import(search_paths=['/dev/gptid'])]
                )
            )
        else:
            pool = first_or_default(
                None,
                self.dispatcher.threaded(
                    lambda: [p.__getstate__() for p in zfs.find_import(search_paths=['/dev/gptid'], name=guid)]
                )
            )

        if not pool:
            raise VerifyException(errno.ENOENT, 'Pool with GUID {0} not found'.format(guid))

        return [f'disk:{d}' for d in get_disk_names(self.dispatcher, pool)]

    def run(self, guid, name=None, properties=None):
        zfs = get_zfs()
        opts = properties or {}
        opts['cachefile'] = USER_CACHE_FILE
        
        try:
            if guid.isdigit():
                pool = first_or_default(
                    lambda p: str(p.guid) == guid,
                    zfs.find_import(search_paths=['/dev/gptid'])
                )
            else:
                pool = first_or_default(
                    None,
                    zfs.find_import(search_paths=['/dev/gptid'], name=guid),
                )

            if not pool:
                raise TaskException(errno.ENOENT, 'Pool {0} not found'.format(guid))

            zfs.import_pool(pool, name or pool.name, opts)
            return name or pool.name, str(pool.guid)
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str)
@description('Exports ZFS pool')
class ZpoolExportTask(ZpoolBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Exporting ZFS pool'

    def describe(self, name):
        return TaskDescription('Exporting ZFS pool {name}', name=name)

    def run(self, name):
        zfs = get_zfs()
        try:
            pool = zfs.get(name)
            zfs.export_pool(pool)
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str)
@description('Destroys an exported pool')
class ZpoolDestroyExportedTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Destroying an exported poool'

    def describe(self, name):
        return TaskDescription('Destroying exported pool {name}', name=name)

    def verify(self, name):
        return ['disk:{0}'.format(d) for d in self.dispatcher.call_sync('disk.query', {'select': 'id'})]

    def run(self, name):
        def check_and_clear_label(path):
            if not path:
                return

            try:
                label = libzfs.read_label(path)
            except OSError:
                return

            if not label or label.get('state') == libzfs.PoolState.DESTROYED or label.get('name') != name:
                return

            try:
                libzfs.clear_label(path)
            except OSError as err:
                self.add_warning(TaskWarning(
                    err.errno,
                    'Failed to remove ZFS label on {0}: {1}'.format(path, err.strerror)
                ))

        for disk in self.dispatcher.call_sync('disk.query'):
            check_and_clear_label(disk['path'])
            check_and_clear_label(q.get(disk, 'status.data_partition_path'))


class ZfsBaseTask(Task):
    def verify(self, *args, **kwargs):
        pool, _ = split_dataset(args[0])
        return [f'zpool:{pool}']


@private
@accepts(str, bool)
@description('Mounts ZFS dataset')
class ZfsDatasetMountTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Mounting ZFS dataset'

    def describe(self, name, recursive=False):
        return TaskDescription('Mounting ZFS dataset {name}', name=name)

    def run(self, name, recursive=False):
        try:
            zfs = get_zfs()
            dataset = zfs.get_dataset(name)
            desired_mountpoint = dataset.properties['mountpoint'].value
            if dataset.mountpoint:
                logger.warning('{0} dataset already mounted at {1}'.format(name, dataset.mountpoint))
                return

            def doit():
                if recursive:
                    dataset.mount_recursive(True)
                else:
                    dataset.mount()

            self.dispatcher.exec_and_wait_for_event(
                'system.fs.mounted',
                lambda args: args['fstype'] == 'zfs' and args['path'] == desired_mountpoint,
                lambda: doit(),
                600
            )
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, bool)
@description('Unmounts ZFS dataset')
class ZfsDatasetUmountTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Unmounting ZFS dataset'

    def describe(self, name, recursive=False):
        return TaskDescription('Unmounting ZFS dataset {name}', name=name)

    def run(self, name, recursive=False):
        try:
            zfs = get_zfs()
            dataset = zfs.get_dataset(name)

            if not dataset.mountpoint:
                return

            def doit():
                if recursive:
                    dataset.umount_recursive()
                else:
                    dataset.umount()

            self.dispatcher.exec_and_wait_for_event(
                'system.fs.unmounted',
                lambda args: args['fstype'] == 'zfs' and args['source'] == name,
                lambda: doit(),
                600
            )
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, h.ref('DatasetType'), h.object())
@description('Creates ZFS dataset')
class ZfsDatasetCreateTask(Task):
    def check_type(self, type):
        try:
            self.type = getattr(libzfs.DatasetType, type)
        except AttributeError:
            raise VerifyException(errno.EINVAL, 'Invalid dataset type: {0}'.format(type))

    @classmethod
    def early_describe(cls):
        return 'Creating ZFS dataset'

    def describe(self, path, type, params=None):
        return TaskDescription('Creating ZFS dataset {name}', name=path)

    def verify(self, path, type, params=None):
        pool_name = path.split('/')[0]
        self.check_type(type)
        return ['zpool:{0}'.format(pool_name)]

    def run(self, path, type, props=None):
        pool_name = path.split('/')[0]
        if not pool_exists(pool_name):
            raise TaskException(errno.ENOENT, 'Pool {0} not found'.format(pool_name))

        self.check_type(type)
        try:
            props = props or {}
            params = {}
            sparse = False

            if props.get('sparse'):
                sparse = True
                del props['sparse']

            for k, v in props.items():
                if v.get('value') is not None:
                    params[k] = v['value']
                    continue

                if v.get('parsed') is not None:
                    params[k] = libzfs.serialize_zfs_prop(k, v['parsed'])
                    continue

            if 'refreservation' in params:
                sparse = True

            zfs = get_zfs()
            pool = zfs.get(path.split('/')[0])
            self.dispatcher.exec_and_wait_for_event(
                'fs.zfs.dataset.created',
                lambda args: args['ds'] == path,
                lambda: pool.create(path, params, fstype=self.type, sparse_vol=sparse),
                600
            )
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, str, h.any_of(bool, None), h.any_of(h.object(), None))
@description('Creates snapshot of ZFS dataset')
class ZfsSnapshotCreateTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Creating ZFS snapshot'

    def describe(self, path, snapshot_name, recursive=False, params=None):
        return TaskDescription('Creating snapshot of ZFS dataset {name}', name=path)

    def run(self, path, snapshot_name, recursive=False, params=None):
        if params:
            params = {k: v['value'] for k, v in params.items()}

        try:
            zfs = get_zfs()
            ds = zfs.get_dataset(path)
            self.dispatcher.exec_and_wait_for_event(
                'fs.zfs.dataset.created',
                lambda args: args['ds'] == '{0}@{1}'.format(path, snapshot_name),
                lambda: ds.snapshot('{0}@{1}'.format(path, snapshot_name), recursive=recursive, fsopts=params),
                600
            )
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, str, h.any_of(bool, None))
@description('Deletes ZFS dataset\'s snapshot')
class ZfsSnapshotDeleteTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting ZFS snapshot'

    def describe(self, path, snapshot_name, recursive=False):
        return TaskDescription('Deleting snapshot {name} of ZFS dataset {path}', name=snapshot_name, path=path)

    def run(self, path, snapshot_name, recursive=False):
        try:
            zfs = get_zfs()
            snap = zfs.get_snapshot('{0}@{1}'.format(path, snapshot_name))
            self.dispatcher.exec_and_wait_for_event(
                'fs.zfs.dataset.deleted',
                lambda args: args['ds'] == '{0}@{1}'.format(path, snapshot_name),
                lambda: snap.delete(recursive),
                600
            )
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, h.array(str), h.any_of(bool, None))
@description('Deletes multiple ZFS dataset\'s snapshots')
class ZfsSnapshotDeleteMultipleTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting ZFS snapshots'

    def describe(self, path, snapshot_names=None, recursive=False):
        return TaskDescription('Deleting snapshots of ZFS dataset {name}', name=path)

    def run(self, path, snapshot_names=None, recursive=False):
        try:
            zfs = get_zfs()

            if snapshot_names is None:
                ds = zfs.get_dataset(path)
                snapshot_names = (i.snapshot_name for i in list(ds.snapshots))

            for i in snapshot_names:
                snap = zfs.get_snapshot('{0}@{1}'.format(path, i))
                self.dispatcher.exec_and_wait_for_event(
                    'fs.zfs.dataset.deleted',
                    lambda args: args['ds'] == '{0}@{1}'.format(path, i),
                    lambda: snap.delete(recursive),
                    600
                )
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@description('Updates ZFS object\'s configuration')
class ZfsConfigureTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Updating configuration of ZFS object'

    def describe(self, name, properties):
        return TaskDescription('Updating configuration of ZFS object {name}', name=name)

    def run(self, name, properties):
        try:
            zfs = get_zfs()
            dataset = zfs.get_object(name)
            for k, v in list(properties.items()):
                if k == 'volblocksize' and dataset.type == libzfs.DatasetType.FILESYSTEM:
                    continue

                if k in dataset.properties:
                    prop = dataset.properties[k]

                    if v.get('source') == 'INHERITED':
                        prop.inherit()
                        continue

                    if 'parsed' in v and prop.parsed != v['parsed']:
                        prop.parsed = v['parsed']
                        continue

                    if 'value' in v and prop.value != v['value']:
                        prop.value = v['value']
                        continue
                else:
                    prop = libzfs.ZFSUserProperty(v['value'])
                    dataset.properties[k] = prop
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@description('Destroys ZFS object')
class ZfsDestroyTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Destroying ZFS object'

    def describe(self, name):
        return TaskDescription('Destroying ZFS object {name}', name=name)

    def run(self, name):
        try:
            zfs = get_zfs()
            dataset = zfs.get_object(name)
            self.dispatcher.exec_and_wait_for_event(
                'fs.zfs.dataset.deleted',
                lambda args: args['ds'] == name,
                lambda: dataset.delete(),
                600
            )
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, str)
@description('Renames ZFS object')
class ZfsRenameTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Renaming ZFS object'

    def describe(self, name, new_name):
        return TaskDescription('Renaming ZFS object {name} to {new_name}', name=name, new_name=new_name)

    def run(self, name, new_name):
        try:
            zfs = get_zfs()
            dataset = zfs.get_object(name)
            self.dispatcher.exec_and_wait_for_event(
                'fs.zfs.dataset.renamed',
                lambda args: args['ds'] == name,
                lambda: dataset.rename(new_name),
                600
            )
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, str)
@description('Clones ZFS snapshot')
class ZfsCloneTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Cloning ZFS snapshot'

    def describe(self, name, new_name):
        return TaskDescription('Cloning ZFS snapshot {name} to {new_name}', name=name, new_name=new_name)

    def run(self, name, new_name):
        try:
            zfs = get_zfs()
            snapshot = zfs.get_snapshot(name)
            self.dispatcher.exec_and_wait_for_event(
                'fs.zfs.snapshot.cloned',
                lambda args: args['ds'] == new_name,
                lambda: snapshot.clone(new_name),
                600
            )
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@accepts(str, bool, bool)
@description('Returns ZFS snapshot to previous state')
class ZfsRollbackTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Returning ZFS snapshot to previous state'

    def describe(self, name, force=False, recursive=False):
        return TaskDescription('Returning ZFS snapshot {name} to previous state', name=name)

    def run(self, name, force=False, recursive=False):
        try:
            zfs = get_zfs()
            if recursive:
                ds_name, snap = name.split('@')
                parent_ds = zfs.get_dataset(ds_name)
                for d in list(parent_ds.dependents):
                    if d.type == libzfs.DatasetType.SNAPSHOT and d.name.endswith(snap):
                        d.rollback(force)
            else:
                snapshot = zfs.get_snapshot(name)
                snapshot.rollback(force)
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))


@private
@description('Sends ZFS replication stream')
class ZfsSendTask(ZfsBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Sending ZFS replication stream'

    def describe(self, name, fromsnap, tosnap, fd):
        return TaskDescription(
            'Sending ZFS replication stream from {fromname} to snapshot {tosnap}',
            fromname='{0}:{1}'.format(name, fromsnap) if fromsnap else name,
            tosnap=tosnap
        )

    def run(self, name, fromsnap, tosnap, fd):
        try:
            zfs = get_zfs()
            obj = zfs.get_object(name)
            obj.send(fd.fd, fromname=fromsnap, toname=tosnap, flags={
                libzfs.SendFlag.PROGRESS,
                libzfs.SendFlag.PROPS
            })
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))
        finally:
            try:
                os.close(fd.fd)
            except OSError:
                pass


@private
@description('Sends ZFS replication stream')
class ZfsResumeSendTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Sending resumed ZFS replication stream'

    def verify(self, token, fd):
        token_info = self.dispatcher.call_sync('zfs.dataset.describe_resume_token', token)
        ds, _, _ = token_info['toname'].partition('@')
        return ['zfs:{0}'.format(ds)]

    def describe(self, token, fd):
        token_info = self.dispatcher.call_sync('zfs.dataset.describe_resume_token', token)
        return TaskDescription(
            'Sending resumed ZFS replication stream from {name}',
            name=token_info['toname'] if token_info else 'unknown'
        )

    def run(self, token, fd):
        try:
            zfs = get_zfs()
            zfs.send_resume(fd.fd, token, flags={
                libzfs.SendFlag.PROGRESS,
                libzfs.SendFlag.PROPS
            })
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))
        finally:
            try:
                os.close(fd.fd)
            except OSError:
                pass


@private
@description('Receives ZFS replication stream')
class ZfsReceiveTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Receiving ZFS replication stream'

    def describe(self, name, fd, force=False, nomount=False, props=None, limitds=None):
        return TaskDescription(
            'Receiving ZFS replication stream into {name} dataset',
            name=name or ''
        )

    def verify(self, name, fd, force=False, nomount=False, props=None, limitds=None):
        try:
            zfs = get_zfs()
            dataset = zfs.get_object(name.split('/')[0])
        except libzfs.ZFSException as err:
            raise TaskException(errno.ENOENT, str(err))

        return ['zpool:{0}'.format(dataset.pool.name)]

    def run(self, name, fd, force=False, nomount=False, props=None, limitds=None):
        try:
            zfs = get_zfs()
            zfs.receive(name, fd.fd, force, nomount, True, props, limitds)
        except libzfs.ZFSException as err:
            raise TaskException(zfs_error_to_errno(err.code), str(err))
        finally:
            try:
                os.close(fd.fd)
            except OSError:
                pass


def convert_topology(zfs, topology):
    nvroot = {}
    for group, vdevs in topology.items():
        nvroot[group] = []
        for i in vdevs:
            vdev = libzfs.ZFSVdev(zfs, "disk")
            vdev.type = i['type']

            if i['type'] == 'disk':
                vdev.path = i['path']

            if 'children' in i:
                ret = []
                for c in i['children']:
                    cvdev = libzfs.ZFSVdev(zfs, "disk")
                    cvdev.type = c['type']
                    cvdev.path = c['path']
                    ret.append(cvdev)

                vdev.children = ret

            nvroot[group].append(vdev)

    return nvroot


def pool_exists(pool):
    try:
        zfs = get_zfs()
        return zfs.get(pool) is not None
    except libzfs.ZFSException:
        return False


def get_disk_names(dispatcher, pool):
    ret = []
    for disk, _ in get_disks(pool['groups']):
        try:
            d = dispatcher.call_sync('disk.partition_to_disk', disk)
        except RpcException:
            continue

        ret.append(d)

    return ret


def sync_zpool_cache(dispatcher, pool, guid=None):
    zfs = get_zfs()
    try:
        oldpool = pools.get(pool)
        zfspool = dispatcher.threaded(lambda: zfs.get(pool).__getstate__(False))

        if oldpool:
            for vd, _ in iterate_vdevs(zfspool['groups']):
                oldvd = vdev_by_guid(oldpool['groups'], vd['guid'])
                if not oldvd:
                    continue

                if vd['status'] != oldvd['status']:
                    dispatcher.emit_event('zfs.pool.vdev_state_changed', {
                        'pool': pool,
                        'guid': zfspool['guid'],
                        'vdev_guid': vd['guid'],
                        'status': vd['status']
                    })

        pools.put(pool, zfspool)
    except libzfs.ZFSException as e:
        if e.code == libzfs.Error.NOENT:
            pools.remove(pool)
            snapshots.remove_predicate(lambda i: i['pool'] == pool)
            datasets.remove_predicate(lambda i: i['pool'] == pool)
            return

        logger.warning("Cannot read pool status from pool {0}".format(pool))


def sync_dataset_cache(dispatcher, dataset, old_dataset=None, recursive=False, snaps=False):
    zfs = get_zfs()
    pool = dataset.split('/')[0]
    sync_zpool_cache(dispatcher, pool)
    try:
        ds = dispatcher.threaded(lambda: zfs.get_dataset(dataset))
        if old_dataset:
            datasets.rename(old_dataset, dataset)

        datasets.put(dataset, dispatcher.threaded(lambda: ds.__getstate__(False)))

        if snaps:
            for i in dispatcher.threaded(lambda: list(ds.snapshots)):
                oldpath = f'{old_dataset}@{i.snapshot_name}' if old_dataset else None
                sync_snapshot_cache(dispatcher, i.name, old_snapshot=oldpath)

        if recursive:
            for i in dispatcher.threaded(lambda: list(ds.children)):
                oldpath = os.path.join(old_dataset, os.path.relpath(i.name, dataset)) if old_dataset else None
                sync_dataset_cache(dispatcher, i.name, old_dataset=oldpath, recursive=True, snaps=snaps)

    except libzfs.ZFSException as e:
        if e.code == libzfs.Error.NOENT:
            if datasets.remove(dataset):
                snapshots.remove_predicate(lambda i: i['dataset'] == dataset)
                datasets.remove_predicate(lambda i: is_child(i['name'], dataset))

            return

        logger.warning("Cannot read dataset status from dataset {0}".format(dataset))


def sync_snapshot_cache(dispatcher, snapshot, old_snapshot=None):
    zfs = get_zfs()
    try:
        if old_snapshot:
            snapshots.rename(old_snapshot, snapshot)

        snapshots.put(snapshot, dispatcher.threaded(lambda: zfs.get_snapshot(snapshot).__getstate__()))
    except libzfs.ZFSException as e:
        if e.code == libzfs.Error.NOENT:
            snapshots.remove(snapshot)
            return

        logger.warning("Cannot read snapshot status from snapshot {0}".format(snapshot))


def zpool_try_clear(dispatcher, name, vdev):
    zfs = get_zfs()
    try:
        pool = zfs.get(name)
        if dispatcher.threaded(pool.clear):
            logger.info('Device {0} reattached successfully to pool {1}'.format(vdev['path'], name))
            return
    except libzfs.ZFSException:
        # Silently ignore pool not found errors
        return

    logger.warning('Device {0} reattach to pool {1} failed'.format(vdev['path'], name))


def zfs_error_to_errno(code):
    mapping = {
        libzfs.Error.NOMEM: errno.ENOMEM,
        libzfs.Error.NOENT: errno.ENOENT,
        libzfs.Error.BUSY: errno.EBUSY,
        libzfs.Error.UMOUNTFAILED: errno.EBUSY,
        libzfs.Error.EXISTS: errno.EEXIST,
        libzfs.Error.PERM: errno.EPERM,
        libzfs.Error.FAULT: errno.EFAULT,
        libzfs.Error.IO: errno.EIO,
        libzfs.Error.NOSPC: errno.ENOSPC
    }

    return mapping.get(code, errno.EFAULT)


def get_zfs():
    global zfs
    if not zfs:
        zfs = libzfs.ZFS(history=True, history_prefix="<dispatcher>")

    return zfs


def collect_debug(dispatcher):
    yield AttachData('pool-cache-state', dumps(pools.query()))
    yield AttachData('dataset-cache-state', dumps(datasets.query()))
    yield AttachData('snapshot-cache-state', dumps(snapshots.query()))
    yield AttachCommandOutput('zpool-status', ['/sbin/zpool', 'status'])
    yield AttachCommandOutput('zpool-history', ['/sbin/zpool', 'history'])
    yield AttachCommandOutput('zpool-list', ['/sbin/zpool', 'get', 'all'])
    yield AttachCommandOutput('zfs-list', ['/sbin/zfs', 'get', 'all'])
    yield AttachCommandOutput('zpool-import', ['/sbin/zpool', 'import'])


def _depends():
    return ['DevdPlugin', 'DiskPlugin']


def _init(dispatcher, plugin):
    @sync
    def on_pool_create(args):
        logger.info('New pool created: {0} <{1}>'.format(args['pool'], args['guid']))
        with dispatcher.get_lock('zfs-cache'):
            sync_zpool_cache(dispatcher, args['pool'], args['guid'])

    @sync
    def on_pool_import(args):
        logger.info('New pool imported: {0} <{1}>'.format(args['pool'], args['guid']))
        with dispatcher.get_lock('zfs-cache'):
            sync_zpool_cache(dispatcher, args['pool'], args['guid'])
            sync_dataset_cache(dispatcher, args['pool'], recursive=True, snaps=True)

    @sync
    def on_pool_destroy(args):
        logger.info('Pool {0} <{1}> destroyed'.format(args['pool'], args['guid']))
        with dispatcher.get_lock('zfs-cache'):
            sync_zpool_cache(dispatcher, args['pool'], args['guid'])

    @sync
    def on_pool_changed(args):
        if args['pool'] == '$import':
            return

        with dispatcher.get_lock('zfs-cache'):
            sync_zpool_cache(dispatcher, args['pool'], args['guid'])

    @sync
    def on_pool_reguid(args):
        logger.info('Pool {0} changed guid to <{1}>'.format(args['pool'], args['guid']))

    @sync
    def on_dataset_create(args):
        with dispatcher.get_lock('zfs-cache'):
            if '@' in args['ds']:
                logger.info('New snapshot created: {0}'.format(args['ds']))
                sync_snapshot_cache(dispatcher, args['ds'])
            else:
                logger.info('New dataset created: {0}'.format(args['ds']))
                sync_dataset_cache(dispatcher, args['ds'], snaps=True)

    @sync
    def on_dataset_delete(args):
        with dispatcher.get_lock('zfs-cache'):
            if '@' in args['ds']:
                logger.info('Snapshot removed: {0}'.format(args['ds']))
                sync_snapshot_cache(dispatcher, args['ds'])
            else:
                logger.info('Dataset removed: {0}'.format(args['ds']))
                sync_dataset_cache(dispatcher, args['ds'], snaps=True)

    @sync
    def on_dataset_rename(args):
        with dispatcher.get_lock('zfs-cache'):
            if '@' in args['ds']:
                logger.info('Snapshot {0} renamed to: {1}'.format(args['ds'], args['new_ds']))
                sync_snapshot_cache(dispatcher, args['new_ds'], args['ds'])
            else:
                logger.info('Dataset {0} renamed to: {1}'.format(args['ds'], args['new_ds']))
                sync_dataset_cache(dispatcher, args['new_ds'], args['ds'], recursive=True, snaps=True)

    @sync
    def on_dataset_setprop(args):
        with dispatcher.get_lock('zfs-cache'):
            if args['action'] == 'set':
                logger.log(TRACE, '{0} {1} property {2} set to: {3}'.format(
                    'Snapshot' if '@' in args['ds'] else 'Dataset',
                    args['ds'],
                    args['prop_name'],
                    args['prop_value']
                ))

            if args['action'] == 'inherit':
                logger.log(TRACE, '{0} {1} property {2} inherited from parent'.format(
                    'Snapshot' if '@' in args['ds'] else 'Dataset',
                    args['ds'],
                    args['prop_name'],
                ))

            if '@' in args['ds']:
                sync_snapshot_cache(dispatcher, args['ds'])
            else:
                sync_dataset_cache(dispatcher, args['ds'], recursive=True)

    @sync
    def on_vfs_mount_or_unmount(type, args):
        if args['fstype'] == 'zfs':
            with dispatcher.get_lock('zfs-cache'):
                if 'source' in args:
                    ds = datasets.query(('id', '=', args['source']), single=True)
                else:
                    ds = datasets.query(('properties.mountpoint.value', '=', args['path']), single=True)

                if not ds:
                    for mnt in dispatcher.threaded(lambda: list(bsd.getmntinfo())):
                        if mnt.dest == args['path']:
                            ds = datasets.query(('id', '=', mnt.source), single=True)
                            if ds:
                                break

                if not ds:
                    return

                logger.info('Dataset {0} {1}ed'.format(ds['name'], type))
                if type == 'mount' and not ds['mountpoint']:
                    datasets.update_one(ds['id'], **{
                        'mountpoint': args['path'],
                        'properties.mounted.rawvalue': 'yes',
                        'properties.mounted.value': 'yes',
                        'properties.mounted.parsed': True
                    })

                if type == 'unmount' and ds['mountpoint']:
                    datasets.update_one(ds['id'], **{
                        'mountpoint': args['path'],
                        'properties.mounted.rawvalue': 'no',
                        'properties.mounted.value': 'no',
                        'properties.mounted.parsed': False
                    })

    @sync
    def on_disk_attached(args):
        for volume in dispatcher.call_sync('volume.query', [('status', 'in', ('DEGRADED', 'UNAVAIL'))]):
            if volume.get('key_encrypted') or volume.get('password_encrypted'):
                continue

            for vd, _ in iterate_vdevs(volume['topology']):
                if args['path'] == vd['path']:
                    logger.info(f'Device {args["path"]} that was part of the pool {volume["id"]} got reconnected')

                    # Try to clear errors
                    zpool_try_clear(dispatcher, volume['id'], vd)

    def sync_sizes():
        zfs = get_zfs()
        interval = dispatcher.configstore.get('middleware.zfs_refresh_interval')
        while True:
            gevent.sleep(interval)
            with dispatcher.get_lock('zfs-cache'):
                for key, i in pools.itervalid():
                    try:
                        zfspool = dispatcher.threaded(lambda: zfs.get(key).__getstate__(False))
                        if zfspool != i:
                            pools.put(key, zfspool)
                    except libzfs.ZFSException:
                        pass

                changed = {}
                for key, i in datasets.itervalid():
                    def doit():
                        props = i['properties']
                        ds = zfs.get_dataset(i['id'])
                        changed = False

                        for prop in VOLATILE_ZFS_PROPERTIES:
                            if props[prop]['rawvalue'] != ds.properties[prop].rawvalue:
                                props[prop] = ds.properties[prop].__getstate__()
                                changed = True

                        return changed

                    try:
                        if dispatcher.threaded(doit):
                            changed[key] = i
                    except libzfs.ZFSException:
                        pass

                datasets.update(**changed)

    plugin.register_schema_definition('ZfsVdev', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'path': {'type': ['string', 'null']},
            'guid': {'type': 'string'},
            'disk_id': {'type': 'string'},
            'status': {
                'type': 'string',
                'readOnly': True
            },
            'stats': {
                'type': 'object',
                'readOnly': True
            },
            'type': {'$ref': 'ZfsVdevType'},
            'children': {
                'type': 'array',
                'items': {'$ref': 'ZfsVdev'}
            }
        }
    })

    plugin.register_schema_definition('ZfsVdevType', {
        'type': 'string',
        'enum': ['disk', 'file', 'mirror', 'raidz1', 'raidz2', 'raidz3']
    })

    plugin.register_schema_definition('ZfsTopology', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'data': {
                'type': 'array',
                'items': {'$ref': 'ZfsVdev'},
            },
            'log': {
                'type': 'array',
                'items': {'$ref': 'ZfsVdev'},
            },
            'cache': {
                'type': 'array',
                'items': {'$ref': 'ZfsVdev'},
            },
            'spare': {
                'type': 'array',
                'items': {'$ref': 'ZfsVdev'},
            },
        }
    })

    plugin.register_schema_definition('ZfsVdevExtension', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'target_guid': {'type': 'string'},
            'vdev': {'$ref': 'ZfsVdev'}
        }
    })

    # TODO: Add ENUM to the 'state' property below
    plugin.register_schema_definition('ZfsScan', {
        'type': 'object',
        'readOnly': True,
        'properties': {
            'errors': {'type': ['integer', 'null']},
            'start_time': {'type': ['datetime', 'null']},
            'bytes_to_process': {'type': ['integer', 'null']},
            'state': {'type': ['string', 'null']},
            'end_time': {'type': ['datetime', 'null']},
            'function': {'type': ['string', 'null']},
            'bytes_processed': {'type': ['integer', 'null']},
            'percentage': {'type': ['number', 'null']},
        }
    })

    plugin.register_schema_definition('ZfsDataset', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'name': {'type': 'string'},
            'pool': {'type': 'string'},
            'type': {'$ref': 'DatasetType'},
            'properties': {
                'type': 'object',
                'additionalProperties': {'$ref': 'ZfsProperty'}
            },
            'children': {
                'type': 'array',
                'items': {'$ref': 'ZfsDataset'},
            },
        }
    })

    plugin.register_schema_definition('DatasetType', {
        'type': 'string',
        'enum': list(libzfs.DatasetType.__members__.keys())
    })

    plugin.register_schema_definition('ZfsSnapshot', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'pool': {'type': 'string'},
            'dataset': {'type': 'string'},
            'type': {'$ref': 'DatasetType'},
            'name': {'type': 'string'},
            'holds': {'type': 'object'},
            'properties': {'type': 'object'}
        }
    })

    plugin.register_schema_definition('ZfsPropertySource', {
        'type': 'string',
        'enum': ['NONE', 'DEFAULT', 'LOCAL', 'INHERITED', 'RECEIVED']
    })

    plugin.register_schema_definition('ZfsProperty', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'source': {'$ref': 'ZfsPropertySource'},
            'value': {'type': 'string'},
            'rawvalue': {'type': 'string'},
            'parsed': {'type': ['string', 'integer', 'boolean', 'datetime', 'null']}
        }
    })

    plugin.register_schema_definition('ZfsPool', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'status': {'$ref': 'ZfsPoolStatus'},
            'name': {'type': 'string'},
            'scan': {'$ref': 'ZfsScan'},
            'hostname': {'type': 'string'},
            'root_dataset': {'$ref': 'ZfsDataset'},
            'groups': {'$ref': 'ZfsTopology'},
            'guid': {'type': 'integer'},
            'properties': {'$ref': 'ZfsProperties'},
        }
    })

    plugin.register_schema_definition('ZfsPoolStatus', {
        'type': 'string',
        'enum': ['ONLINE', 'OFFLINE', 'DEGRADED', 'FAULTED', 'REMOVED', 'UNAVAIL']
    })

    plugin.register_schema_definition('ZfsResumeToken', {
        'fromguid': {'type': 'integer'},
        'object': {'type': 'integer'},
        'offset': {'type': 'integer'},
        'bytes': {'type': 'integer'},
        'toguid': {'type': 'integer'},
        'toname': {'type': 'string'}
    })

    # Register Providers
    plugin.register_provider('zfs.pool', ZpoolProvider)
    plugin.register_provider('zfs.dataset', ZfsDatasetProvider)
    plugin.register_provider('zfs.snapshot', ZfsSnapshotProvider)

    # Register Event Types
    plugin.register_event_type('zfs.pool.changed')
    plugin.register_event_type('zfs.pool.vdev_state_changed')
    plugin.register_event_type('zfs.dataset.changed')
    plugin.register_event_type('zfs.snapshot.changed')

    # Register Task Handlers
    plugin.register_task_handler('zfs.pool.create', ZpoolCreateTask)
    plugin.register_task_handler('zfs.pool.update', ZpoolConfigureTask)
    plugin.register_task_handler('zfs.pool.extend', ZpoolExtendTask)
    plugin.register_task_handler('zfs.pool.detach', ZpoolDetachTask)
    plugin.register_task_handler('zfs.pool.replace', ZpoolReplaceTask)
    plugin.register_task_handler('zfs.pool.offline_disk', ZpoolOfflineDiskTask)
    plugin.register_task_handler('zfs.pool.online_disk', ZpoolOnlineDiskTask)
    plugin.register_task_handler('zfs.pool.upgrade', ZpoolUpgradeTask)

    plugin.register_task_handler('zfs.pool.import', ZpoolImportTask)
    plugin.register_task_handler('zfs.pool.export', ZpoolExportTask)
    plugin.register_task_handler('zfs.pool.destroy', ZpoolDestroyTask)
    plugin.register_task_handler('zfs.pool.destroy_exported', ZpoolDestroyExportedTask)
    plugin.register_task_handler('zfs.pool.scrub', ZpoolScrubTask)

    plugin.register_task_handler('zfs.mount', ZfsDatasetMountTask)
    plugin.register_task_handler('zfs.umount', ZfsDatasetUmountTask)
    plugin.register_task_handler('zfs.create_dataset', ZfsDatasetCreateTask)
    plugin.register_task_handler('zfs.create_snapshot', ZfsSnapshotCreateTask)
    plugin.register_task_handler('zfs.delete_snapshot', ZfsSnapshotDeleteTask)
    plugin.register_task_handler('zfs.delete_multiple_snapshots', ZfsSnapshotDeleteMultipleTask)
    plugin.register_task_handler('zfs.update', ZfsConfigureTask)
    plugin.register_task_handler('zfs.destroy', ZfsDestroyTask)
    plugin.register_task_handler('zfs.rename', ZfsRenameTask)
    plugin.register_task_handler('zfs.clone', ZfsCloneTask)
    plugin.register_task_handler('zfs.rollback', ZfsRollbackTask)
    plugin.register_task_handler('zfs.send', ZfsSendTask)
    plugin.register_task_handler('zfs.send_resume', ZfsResumeSendTask)
    plugin.register_task_handler('zfs.receive', ZfsReceiveTask)

    # Register debug hook
    plugin.register_debug_hook(collect_debug)

    if not os.path.isdir('/data/zfs'):
        os.mkdir('/data/zfs')

    # Import user volumes, first from the designated cache file and then by looking at on-disk labels
    logger.info('Importing user volumes')
    try:
        zfs = get_zfs()
        opts = {'cachefile': USER_CACHE_FILE}

        for pool in dispatcher.threaded(lambda: list(zfs.find_import(cachefile=USER_CACHE_FILE))):
            volume = dispatcher.datastore.get_by_id('volumes', pool.name)
            if volume and (volume.get('key_encrypted') or volume.get('password_encrypted')):
                continue

            try:
                logger.info('Importing pool {0} <{1}>'.format(pool.name, pool.guid))
                dispatcher.threaded(zfs.import_pool, pool, pool.name, opts)

                # Mount the volume
                logger.info('Mounting pool {0}'.format(pool.name))
                ds = dispatcher.threaded(zfs.get_dataset, pool.name)
                dispatcher.threaded(ds.mount_recursive, True)
            except libzfs.ZFSException as err:
                logger.error('Cannot import user pool {0}: {1}'.format(pool.name, str(err)))
                continue

        # Try to reimport Pools into the system after upgrade, this checks
        # for any non-imported pools in the system via the python binding
        # analogous of `zpool import` and then tries to verify its guid with
        # the pool's in the database. In the event two pools with the same guid
        # are found (Very rare and only happens in special broken cases) it
        # logs said guid with pool name and skips that import.
        unimported_unique_pools = {}
        unimported_duplicate_pools = []

        for pool in dispatcher.threaded(lambda: list(zfs.find_import(search_paths=['/dev/gptid']))):
            volume = dispatcher.datastore.get_by_id('volumes', pool.name)
            if volume and (volume.get('key_encrypted') or volume.get('password_encrypted')):
                continue

            if pool.guid in unimported_unique_pools:
                # This means that the pool is prolly a duplicate
                # Thus remove it from this dict of pools
                # and put it in the duplicate dict
                del unimported_unique_pools[pool.guid]
                unimported_duplicate_pools.append(pool)
            else:
                # Since there can be more than two duplicate copies
                # of a pool might exist, we still need to check for
                # it in the unimported pool list
                duplicate_guids = [x.guid for x in unimported_duplicate_pools]
                if pool.guid in duplicate_guids:
                    continue
                else:
                    unimported_unique_pools[pool.guid] = pool

        # Logging the duplicate pool names and guids, if any
        if unimported_duplicate_pools:
            logger.warning(
                'The following pools were unimported because of duplicates' +
                'being found:'
            )

            for duplicate_pool in unimported_duplicate_pools:
                logger.warning('Unimported pool name: {0}, guid: {1}'.format(
                    duplicate_pool.name,
                    duplicate_pool.guid
                ))

        # Finally, Importing the unique unimported pools that are present in
        # the database
        volumes = dispatcher.datastore.query_stream(
            'volumes',
            ('key_encrypted', '!=', True),
            ('password_encrypted', '!=', True)
        )
        for vol in volumes:
            if int(vol['guid']) in unimported_unique_pools:
                pool_to_import = unimported_unique_pools[int(vol['guid'])]
                # Check if the volume name is also the same
                if vol['id'] == pool_to_import.name:
                    try:
                        logger.info('Importing pool {0} <{1}>'.format(vol['id'], vol['guid']))
                        dispatcher.threaded(zfs.import_pool, pool_to_import, pool_to_import.name, opts)

                        # Mount the volume
                        logger.info('Mounting pool {0}'.format(vol['id']))
                        ds = dispatcher.threaded(zfs.get_dataset, vol['id'])
                        dispatcher.threaded(ds.mount_recursive, True)
                    except libzfs.ZFSException as err:
                        logger.error('Cannot import pool {0} <{1}>: {2}'.format(
                            pool_to_import.name,
                            vol['guid'],
                            str(err))
                        )
                else:
                    # What to do now??
                    # When in doubt log it!
                    logger.error(
                        'Cannot Import pool with guid: {0}'.format(vol['guid']) +
                        ' because it is named as: {0} in'.format(vol['id']) +
                        ' the database but the actual system found it named' +
                        ' as {0}'.format(pool_to_import.name)
                    )

            # Try to correct cachefile and clear errors if there are any
            try:
                def doit():
                    z = get_zfs()
                    pool = z.get(vol['id'])
                    pool.clear()
                    cachefile = pool.properties['cachefile']
                    if cachefile.source == libzfs.PropertySource.DEFAULT:
                        cachefile.value = USER_CACHE_FILE
                        ds = zfs.get_dataset(pool.name)
                        ds.mount_recursive(True)

                dispatcher.threaded(doit)
            except libzfs.ZFSException:
                pass

    except libzfs.ZFSException as err:
        logger.error('Error during pool import: {0}'.format(str(err)))

    # Register event handlers
    plugin.register_event_handler('fs.zfs.pool.created', on_pool_create)
    plugin.register_event_handler('fs.zfs.pool.imported', on_pool_import)
    plugin.register_event_handler('fs.zfs.pool.destroyed', on_pool_destroy)
    plugin.register_event_handler('fs.zfs.pool.setprop', on_pool_changed)
    plugin.register_event_handler('fs.zfs.pool.reguid', on_pool_reguid)
    plugin.register_event_handler('fs.zfs.pool.config_sync', on_pool_changed)
    plugin.register_event_handler('fs.zfs.vdev.state_changed', on_pool_changed)
    plugin.register_event_handler('fs.zfs.vdev.removed', on_pool_changed)
    plugin.register_event_handler('fs.zfs.dataset.created', on_dataset_create)
    plugin.register_event_handler('fs.zfs.dataset.deleted', on_dataset_delete)
    plugin.register_event_handler('fs.zfs.dataset.renamed', on_dataset_rename)
    plugin.register_event_handler('fs.zfs.dataset.setprop', on_dataset_setprop)
    plugin.register_event_handler('fs.zfs.snapshot.cloned', on_dataset_create)
    plugin.register_event_handler('disk.attached', on_disk_attached)
    plugin.register_event_handler('system.fs.mounted', lambda a: on_vfs_mount_or_unmount('mount', a))
    plugin.register_event_handler('system.fs.unmounted', lambda a: on_vfs_mount_or_unmount('unmount', a))

    # Do initial cache sync
    zfs_cache_start = time.time()
    try:
        global pools
        global datasets
        global snapshots

        zfs = get_zfs()
        msg = "Syncing ZFS pools..."
        logger.info(msg)
        plugin.push_status(msg)

        def sort_func(d):
            return os.path.dirname(d), os.path.basename(d)

        def snap_sort_func(d):
            ds, snap = d.split('@', 1)
            par, base = sort_func(ds)
            return par, base, snap

        pools = EventCacheStore(dispatcher, 'zfs.pool', sort_func)
        datasets = EventCacheStore(dispatcher, 'zfs.dataset', sort_func)
        snapshots = EventCacheStore(dispatcher, 'zfs.snapshot', snap_sort_func)

        pools_dict = {}
        for i in dispatcher.threaded(lambda: [p.__getstate__(False) for p in zfs.pools]):
            name = i['name']
            pools_dict[name] = i
        pools.update(**pools_dict)

        msg = "Syncing ZFS datasets..."
        logger.info(msg)
        plugin.push_status(msg)

        datasets_dict = {}
        for i in dispatcher.threaded(lambda: [d.__getstate__(False) for d in zfs.datasets]):
            name = i['id']
            datasets_dict[name] = i
        datasets.update(**datasets_dict)

        msg = "Syncing ZFS snapshots..."
        logger.info(msg)
        plugin.push_status(msg)

        snapshots_dict = {}
        for i in dispatcher.threaded(lambda: [s.__getstate__() for s in zfs.snapshots]):
            snapshots_dict[i['id']] = i
        snapshots.update(**snapshots_dict)

        pools.ready = True
        datasets.ready = True
        snapshots.ready = True
    except libzfs.ZFSException as err:
        logger.error("Cannot sync ZFS caches: {0}".format(str(err)))
    finally:
        logger.info("Syncing ZFS cache took {0:.0f} ms".format((time.time() - zfs_cache_start) * 1000))

    gevent.spawn(sync_sizes)

    dispatcher.track_resources(
        'zfs.pool.query',
        'entity-subscriber.zfs.pool.changed',
        lambda id: f'zpool:{id}',
        lambda pool: [f'disk:{d}' for d in get_disk_names(dispatcher, pool)]
    )

    dispatcher.track_resources(
        'zfs.dataset.query',
        'entity-subscriber.zfs.dataset.changed',
        lambda id: f'zfs:{id}',
        lambda dataset: [f'zpool:{dataset["pool"]}']
    )
