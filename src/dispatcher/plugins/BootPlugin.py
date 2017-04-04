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
import sys
import errno
import logging
import bsd
from datetime import datetime
from task import Provider, Task, ProgressTask, TaskException, query, TaskDescription
from cache import EventCacheStore
from utils import split_dataset
from debug import AttachCommandOutput
from lib.zfs import vdev_by_path, iterate_vdevs
from freenas.dispatcher.rpc import accepts, returns, description, SchemaHelper as h, generator
from freenas.utils import include, first_or_default, query as q

sys.path.append('/usr/local/lib')
from freenasOS.Update import ListClones, FindClone, RenameClone, ActivateClone, DeleteClone, CreateClone, CloneSetAttr
from freenas.dispatcher.rpc import RpcException, private
from freenas.utils import include, query as q
from freenas.utils.lazy import lazy
from task import VerifyException
from lib.zfs import iterate_vdevs


logger = logging.getLogger(__name__)
bootenvs = None


@description("Provides information on Boot pool")
class BootPoolProvider(Provider):
    @returns(h.ref('ZfsPool'))
    def get_config(self):
        pool = self.dispatcher.call_sync('zfs.pool.get_boot_pool')

        @lazy
        def collect_disks():
            disks = []
            for vdev, _ in iterate_vdevs(pool['groups']):
                disk_id = None
                disk = None

                try:
                    disk_id = self.dispatcher.call_sync('disk.partition_to_disk', vdev['path'])
                    disk = self.dispatcher.call_sync(
                        'disk.query',
                        [('id', '=', disk_id), ('online', '=', True)],
                        {'single': True}
                    )
                except RpcException:
                    pass

                disks.append({
                    'disk_id': disk_id,
                    'path': q.get(disk, 'path', vdev['path']),
                    'guid': vdev['guid'],
                    'status': vdev['status']
                })

            return disks

        return {
            'name': pool['id'],
            'guid': pool['guid'],
            'status': pool['status'],
            'scan': pool['scan'],
            'properties': include(
                pool['properties'],
                'size', 'capacity', 'health', 'version', 'delegation', 'failmode',
                'autoreplace', 'dedupratio', 'free', 'allocated', 'readonly',
                'comment', 'expandsize', 'fragmentation', 'leaked'
            ),
            'disks': collect_disks
        }

    @private
    @returns(bool)
    def made_of_good_disks(self):
        pool = self.dispatcher.call_sync('boot.pool.query')
        disks = self.dispatcher.call_sync('disk.query', [('id', 'in', pool['disks'])])

        for d in disks:
            if q.get(d, 'controller.controller_name') == 'umass-sim':
                return False

        return True



@description("Provides information on Boot Environments")
class BootEnvironmentsProvider(Provider):
    @query('BootEnvironment')
    @generator
    def query(self, filter=None, params=None):
        return bootenvs.query(*(filter or []), stream=True, **(params or {}))


@description(
    "Creates a clone of the current Boot Environment or of the specified source (optional)"
)
@accepts(str, h.any_of(str, None))
class BootEnvironmentCreate(Task):
    @classmethod
    def early_describe(cls):
        return "Cloning Boot Environment"

    def describe(self, newname, source=None):
        return TaskDescription("Cloning Boot Environment {source} - new name {name}", name=newname, source=source or '')

    def verify(self, newname, source=None):
        return ['system']

    def run(self, newname, source=None):
        def doit():
            try:
                if not CreateClone(newname, bename=source):
                    raise TaskException(errno.EIO, f'Cannot create the {newname} boot environment')
            except KeyError:
                raise TaskException(errno.EEXIST, f'Boot environment {newname} already exists')

        self.dispatcher.exec_and_wait_for_event(
            'boot.environment.changed',
            lambda args: args['operation'] == 'create' and newname in args['ids'],
            doit,
            600
        )


@description("Activates the specified Boot Environment to be selected on reboot")
@accepts(str)
class BootEnvironmentActivate(Task):
    @classmethod
    def early_describe(cls):
        return "Activating the Boot Environment"

    def describe(self, name):
        return TaskDescription("Activating the Boot Environment {name}", name=name)

    def verify(self, name):
        return ['system']

    def run(self, name):
        be = FindClone(name)
        if not be:
            raise TaskException(errno.ENOENT, 'Boot environment {0} not found'.format(name))

        if not ActivateClone(name):
            raise TaskException(errno.EIO, 'Cannot activate the {0} boot environment'.format(name))


@description("Renames the given Boot Environment with the alternate name provieded")
@accepts(str, h.ref('BootEnvironment'))
class BootEnvironmentUpdate(Task):
    @classmethod
    def early_describe(cls):
        return "Updating Boot Environment"

    def describe(self, id, be):
        return TaskDescription("Updating the Boot Environment {name}", name=id)

    def verify(self, id, be):
        return ['system']

    def run(self, id, updated_params):
        boot_pool_name = self.configstore.get('system.boot_pool_name')
        new_id = updated_params.get('id', id)
        be = FindClone(id)
        if not be:
            raise TaskException(errno.ENOENT, 'Boot environment {0} not found'.format(id))

        if not include(updated_params, 'id', 'keep', 'active'):
            return

        def doit():
            if 'id' in updated_params:
                if not RenameClone(id, updated_params['id']):
                    raise TaskException(errno.EIO, 'Cannot rename the {0} boot evironment'.format(id))

            if 'keep' in updated_params:
                self.run_subtask_sync('zfs.update', f'{boot_pool_name}/ROOT/{be["realname"]}', {
                    'beadm:keep': {'value': str(updated_params['keep'])}
                })

            if updated_params.get('active'):
                if not ActivateClone(id):
                    raise TaskException(errno.EIO, 'Cannot activate the {0} boot environment'.format(id))

        self.dispatcher.exec_and_wait_for_event(
            'boot.environment.changed',
            lambda args: args['operation'] == 'update' and (id in args['ids'] or new_id in args['ids']),
            doit,
            600
        )


@description("Deletes the given Boot Environments. Note: It cannot delete an activated BE")
@accepts(str)
class BootEnvironmentsDelete(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting Boot Environment"

    def describe(self, id):
        return TaskDescription("Deleting the Boot Environment {name}", name=id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        be = FindClone(id)
        if not be:
            raise TaskException(errno.ENOENT, 'Boot environment {0} not found'.format(id))

        def doit():
            if not DeleteClone(id):
                raise TaskException(errno.EIO, 'Cannot delete the {0} boot environment'.format(id))

        self.dispatcher.exec_and_wait_for_event(
            'boot.environment.changed',
            lambda args: args['operation'] == 'delete' and id in args['ids'],
            doit,
            600
        )


@description("Attaches the given disk to the boot pool")
@accepts(str, str)
class BootAttachDisk(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Attaching disk to the boot pool"

    def describe(self, disk):
        return TaskDescription("Attaching the {name} disk to the boot pool", name=disk)

    def verify(self, disk):
        boot_pool_name = self.configstore.get('system.boot_pool_name')
        disk_id = self.dispatcher.call_sync('disk.path_to_id', disk)
        if not disk_id:
            raise VerifyException(f'Disk {disk} not found')

        return [f'zpool:{boot_pool_name}', f'disk:{disk_id}']

    def run(self, disk):
        pool = self.dispatcher.call_sync('zfs.pool.get_boot_pool')
        guid = q.get(pool, 'groups.data.0.guid')
        disk_id = self.dispatcher.call_sync('disk.path_to_id', disk)

        # Format disk
        self.run_subtask_sync('disk.format.boot', disk_id)
        self.set_progress(20)

        # Attach disk to the pool
        boot_pool_name = self.configstore.get('system.boot_pool_name')
        self.run_subtask_sync(
            'zfs.pool.extend',
            boot_pool_name,
            None,
            [{
                'target_guid': guid,
                'vdev': {
                    'type': 'disk',
                    'path': os.path.join('/dev', disk + 'p2')
                }
            }],
            progress_callback=lambda p, m, e: self.chunk_progress(20, 80, '', p, m, e)
        )

        self.set_progress(80)

        # Install grub
        disk_id = self.dispatcher.call_sync('disk.path_to_id', disk)
        self.run_subtask_sync('disk.install_bootloader', disk_id)
        self.set_progress(100)


@description("Replaces a disk in the boot pool")
@accepts(str, str)
class BootReplaceDisk(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Replacing disk in the boot pool"

    def describe(self, olddisk, newdisk):
        return TaskDescription(
            "Replacing the {name} disk in the boot pool with {newdisk}",
            name=olddisk,
            newdisk=newdisk
        )

    def verify(self, olddisk, newdisk):
        boot_pool_name = self.configstore.get('system.boot_pool_name')
        return ['zpool:{0}'.format(boot_pool_name)]

    def run(self, olddisk, newdisk):
        olddisk = os.path.join('/dev', olddisk)
        newdisk = os.path.join('/dev', newdisk)
        pool = self.dispatcher.call_sync('zfs.pool.get_boot_pool')
        vdev = vdev_by_path(pool['groups'], olddisk + 'p2')
        disk_id = self.dispatcher.call_sync('disk.path_to_id', newdisk)

        # Format disk
        self.run_subtask_sync('disk.format.boot', disk_id)
        self.set_progress(20)

        # Replace disk in a pool
        boot_pool_name = self.configstore.get('system.boot_pool_name')
        self.run_subtask_sync(
            'zfs.pool.replace',
            boot_pool_name,
            vdev['guid'],
            {
                'type': 'disk',
                'path': newdisk + 'p2',
            },
            progress_callback=lambda p, m, e: self.chunk_progress(20, 80, '', p, m, e)
        )

        # Install grub. Re-fetch disk id, it might have changed during disk format
        disk_id = self.dispatcher.call_sync('disk.path_to_id', newdisk)
        self.run_subtask_sync('disk.install_bootloader', disk_id)
        self.set_progress(100)


@description("Detaches the specified disk from the boot pool")
@accepts(str)
class BootDetachDisk(Task):
    @classmethod
    def early_describe(cls):
        return "Detaching disk from the Boot Pool"

    def describe(self, disk):
        return TaskDescription("Detaching the {name} disk from the Boot Pool", name=disk)

    def verify(self, disk):
        boot_pool_name = self.configstore.get('system.boot_pool_name')
        return ['zpool:{0}'.format(boot_pool_name)]

    def run(self, disk):
        boot_pool_name = self.configstore.get('system.boot_pool_name')
        pool = self.dispatcher.call_sync('zfs.pool.get_boot_pool')
        vdev = first_or_default(
            lambda v: os.path.join('/dev', disk + 'p2') == v['path'],
            q.get(pool, 'groups.data.0.children')
        )
        if not vdev:
            raise TaskException(errno.ENOENT, 'Disk {0} not found in the boot pool'.format(disk))

        self.run_subtask_sync('zfs.pool.detach', boot_pool_name, vdev['guid'])


@description("Scrubs the boot pool")
class BootPoolScrubTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Performing a scrub of the boot pool"

    def describe(self):
        return TaskDescription("Performing a scrub of the boot pool")

    def verify(self):
        return []

    def abort(self):
        self.abort_subtasks()

    def run(self):
        boot_pool_id = self.configstore.get('system.boot_pool_name')
        self.run_subtask_sync(
            'zfs.pool.scrub', boot_pool_id,
            progress_callback=self.set_progress
        )


def collect_debug(dispatcher):
    yield AttachCommandOutput('beadm-list', ['/usr/local/sbin/beadm', 'list'])


def _depends():
    return ['DiskPlugin', 'ZfsPlugin']


def _init(dispatcher, plugin):
    global bootenvs

    boot_pool_name = dispatcher.configstore.get('system.boot_pool_name')
    bootenvs = EventCacheStore(dispatcher, 'boot.environment')

    plugin.register_schema_definition('BootPool', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'name': {'type': 'string'},
            'guid': {'type': 'string'},
            'status': {'$ref': 'VolumeStatus'},
            'scan': {'$ref': 'ZfsScan'},
            'properties': {'$ref': 'VolumeProperties'},
            'disks': {
                'type': 'array',
                'items': {'$ref': 'BootPoolDisk'}
            }
        }
    })

    plugin.register_schema_definition('BootPoolDisk', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'disk_id': {'type': 'string'},
            'guid': {'type': 'string'},
            'status': {'type': 'string'},
            'path': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('BootEnvironment', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'realname': {'type': 'string', 'readOnly': True},
            'active': {'type': 'boolean'},
            'keep': {'type': 'boolean'},
            'on_reboot': {'type': 'boolean', 'readOnly': True},
            'mountpoint': {'type': ['string', 'null'], 'readOnly': True},
            'space': {'type': 'integer', 'readOnly': True},
            'created': {'type': 'datetime', 'readOnly': True}
        }
    })

    def convert_bootenv(boot_pool, ds):
        root_mount = dispatcher.threaded(bsd.statfs, '/')
        path = ds['id'].split('/')

        if len(path) != 3:
            return

        if path[:2] != [boot_pool['id'], 'ROOT']:
            return

        return {
            'active': root_mount.source == ds['id'],
            'keep': q.get(ds, 'properties.beadm:keep.value') not in ('no', 'off', 'False'),
            'on_reboot': q.get(boot_pool, 'properties.bootfs.value') == ds['id'],
            'id': q.get(ds, 'properties.beadm:nickname.value', path[-1]),
            'space': q.get(ds, 'properties.used.parsed'),
            'realname': path[-1],
            'mountpoint': ds.get('mountpoint'),
            'created': datetime.fromtimestamp(int(q.get(ds, 'properties.creation.rawvalue')))
        }

    def on_pool_change(args):
        with dispatcher.get_lock('bootenvs'):
            if args['operation'] != 'update':
                return

            for i in args['entities']:
                if i['id'] != boot_pool_name:
                    continue

                dispatcher.dispatch_event('boot.pool.changed', {
                    'operation': 'update'
                })

                be = bootenvs.query(('on_reboot', '=', True), single=True)
                be_realname = q.get(i, 'properties.bootfs.value').split('/')[-1]

                if be and be_realname == be['realname']:
                    return

                if be:
                    be['on_reboot'] = False
                    bootenvs.put(be['id'], be)

                new_be = bootenvs.query(('realname', '=', be_realname), single=True)
                new_be['on_reboot'] = True
                bootenvs.put(new_be['id'], new_be)

    def on_dataset_change(args):
        if args['operation'] == 'create':
            with dispatcher.get_lock('bootenvs'):
                boot_pool = dispatcher.call_sync('zfs.pool.get_boot_pool')
                bootenvs.propagate(args, lambda x: convert_bootenv(boot_pool, x))

        if args['operation'] == 'delete':
            for i in args['ids']:
                pool, dataset = split_dataset(i)
                if pool != boot_pool_name:
                    continue

                with dispatcher.get_lock('bootenvs'):
                    realname = dataset.split('/')[-1]
                    ds = bootenvs.query(('realname', '=', realname), single=True)
                    if ds:
                        bootenvs.remove(ds['id'])

        if args['operation'] == 'update':
            boot_pool = None
            for i in args['entities']:
                pool, dataset = split_dataset(i['id'])
                if pool != boot_pool_name:
                    continue

                with dispatcher.get_lock('bootenvs'):
                    realname = dataset.split('/')[-1]
                    ds = bootenvs.query(('realname', '=', realname), single=True)
                    if not ds:
                        continue

                    nickname = q.get(i, 'properties.beadm:nickname.value', realname)
                    if nickname and nickname != ds['id']:
                        bootenvs.rename(ds['id'], nickname)

                    if not boot_pool:
                        boot_pool = dispatcher.call_sync('zfs.pool.get_boot_pool')

                    bootenvs.put(nickname, convert_bootenv(boot_pool, i))

    plugin.register_provider('boot.pool', BootPoolProvider)
    plugin.register_provider('boot.environment', BootEnvironmentsProvider)

    plugin.register_event_type('boot.environment.changed')
    plugin.register_event_type('boot.pool.changed')

    plugin.register_task_handler('boot.environment.clone', BootEnvironmentCreate)
    plugin.register_task_handler('boot.environment.activate', BootEnvironmentActivate)
    plugin.register_task_handler('boot.environment.update', BootEnvironmentUpdate)
    plugin.register_task_handler('boot.environment.delete', BootEnvironmentsDelete)

    plugin.register_task_handler('boot.disk.attach', BootAttachDisk)
    plugin.register_task_handler('boot.disk.detach', BootDetachDisk)
    plugin.register_task_handler('boot.disk.replace', BootReplaceDisk)
    plugin.register_task_handler('boot.pool.scrub', BootPoolScrubTask)

    with bootenvs.lock:
        boot_pool = dispatcher.call_sync('zfs.pool.get_boot_pool')
        bootenvs.populate(
            dispatcher.call_sync('zfs.dataset.query'),
            lambda x: convert_bootenv(boot_pool, x)
        )

        plugin.register_event_handler('entity-subscriber.zfs.dataset.changed', on_dataset_change)
        plugin.register_event_handler('entity-subscriber.zfs.pool.changed', on_pool_change)
        bootenvs.ready = True
