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
import stat
import errno
import uuid
import logging
import shutil
import time
import tempfile
import signal
import libzfs
from bsd.copy import copytree
from resources import Resource
from freenas.dispatcher.rpc import RpcException, accepts, returns, description, private
from freenas.dispatcher.rpc import SchemaHelper as h
from task import Task, ProgressTask, Provider, TaskException, TaskDescription


SYSTEM_DIR = '/var/db/system'
logger = logging.getLogger('SystemDataset')


def link_directories(dispatcher):
    for name, d in dispatcher.configstore.get('system.dataset.layout').items():
        target = os.path.join(SYSTEM_DIR, name.replace('+', '.'))

        if not os.path.isdir(target):
            try:
                os.mkdir(target)
            except OSError as err:
                if err.errno != errno.EEXIST:
                    logger.warning('Cannot create skeleton directory {0}: {1}'.format(
                        target,
                        str(err))
                    )
                    continue

        if 'link' in d:
            if not os.path.islink(d['link']) or not os.readlink(d['link']) == target:
                if os.path.exists(d['link']):
                    shutil.move(d['link'], d['link'] + '.{0}.bak'.format(int(time.time())))
                os.symlink(target, d['link'])

        if hasattr(d, 'owner'):
            user = dispatcher.call_sync('user.query', [('username', '=', d['owner'])], {'single': True})
            group = dispatcher.call_sync('group.query', [('name', '=', d['group'])], {'single': True})
            if user and group:
                os.chown(target, user['uid'], group['gid'])

        for cname, c in d.get('children', {}).items():
            cname = cname.replace('+', '.')
            try:
                os.mkdir(os.path.join(target, cname))
            except OSError as err:
                if err.errno != errno.EEXIST:
                    logger.warning('Cannot create skeleton directory {0}: {1}'.format(
                        os.path.join(target, cname),
                        str(err))
                    )

            if 'owner' in c:
                user = dispatcher.call_sync('user.query', [('username', '=', c['owner'])], {'single': True})
                group = dispatcher.call_sync('group.query', [('name', '=', c['group'])], {'single': True})
                if user and group:
                    os.chown(os.path.join(target, cname), user['uid'], group['gid'])


def create_system_dataset(dispatcher, dsid, pool):
    logger.warning('Creating system dataset on pool {0}'.format(pool))
    zfs = libzfs.ZFS()
    pool = zfs.get(pool)

    try:
        ds = zfs.get_dataset('{0}/.system-{1}'.format(pool.name, dsid))
    except libzfs.ZFSException:
        pool.create('{0}/.system-{1}'.format(pool.name, dsid), {
            'mountpoint': 'none',
            'sharenfs': 'off'
        })
        ds = zfs.get_dataset('{0}/.system-{1}'.format(pool.name, dsid))

    try:
        ds.properties['org.freenas:hidden'] = libzfs.ZFSUserProperty('yes')
        ds.properties['canmount'].value = 'noauto'
        ds.properties['mountpoint'].value = SYSTEM_DIR
        ds.properties['aclmode'].value = 'passthrough'
        ds.properties['aclinherit'].value = 'passthrough'
    except libzfs.ZFSException as err:
        logger.warning('Cannot set properties on .system dataset: {0}'.format(str(err)))


def remove_system_dataset(dispatcher, dsid, pool):
    logger.warning('Removing system dataset from pool {0}'.format(pool))
    zfs = libzfs.ZFS()
    pool = zfs.get(pool)
    try:
        ds = zfs.get_dataset('{0}/.system-{1}'.format(pool.name, dsid))
        ds.umount(force=True)
        ds.delete()
    except libzfs.ZFSException:
        pass


def mount_system_dataset(dispatcher, dsid, pool, path):
    logger.warning('Mounting system dataset from pool {0} on {1}'.format(pool, path))
    zfs = libzfs.ZFS()
    pool = zfs.get(pool)
    try:
        ds = zfs.get_dataset('{0}/.system-{1}'.format(pool.name, dsid))
        if ds.mountpoint:
            logger.warning('.system dataset already mounted')
            return

        ds.properties['mountpoint'].value = path
        ds.mount()
    except libzfs.ZFSException as err:
        logger.error('Cannot mount .system dataset on pool {0}: {1}'.format(pool.name, str(err)))
        raise err


def umount_system_dataset(dispatcher, dsid, pool):
    zfs = libzfs.ZFS()
    pool = zfs.get(pool)
    try:
        ds = zfs.get_dataset('{0}/.system-{1}'.format(pool.name, dsid))
        ds.umount(force=True)
        return
    except libzfs.ZFSException as err:
        logger.error('Cannot unmount .system dataset on pool {0}: {1}'.format(pool.name, str(err)))


def import_system_dataset(dispatcher, services, src_pool, old_pool, old_id):
    logger.warning('Importing system dataset from pool {0}'.format(src_pool))

    system_dataset = dispatcher.call_sync(
        'zfs.dataset.query',
        [('pool', '=', src_pool), ('name', '~', '.system')],
        {'single': True}
    )
    id = system_dataset['name'][-8:]

    for s in services:
        dispatcher.call_sync('service.ensure_stopped', s)

    dispatcher.call_sync('management.stop_logdb')

    umount_system_dataset(dispatcher, old_id, old_pool)
    mount_system_dataset(dispatcher, id, src_pool, SYSTEM_DIR)
    remove_system_dataset(dispatcher, old_id, old_pool)

    dispatcher.call_sync('management.start_logdb')

    for s in services:
        dispatcher.call_sync('service.ensure_started', s, timeout=20)

    return id


@description('Provides information about System Dataset')
class SystemDatasetProvider(Provider):
    @private
    @description("Initializes the .system dataset")
    @accepts()
    def init(self):
        pool = self.configstore.get('system.dataset.pool')
        dsid = self.configstore.get('system.dataset.id')
        create_system_dataset(self.dispatcher, dsid, pool)
        mount_system_dataset(self.dispatcher, dsid, pool, SYSTEM_DIR)
        link_directories(self.dispatcher)

    @private
    @description("Creates directory in .system dataset and returns reference to it")
    @accepts(str)
    @returns(str)
    def request_directory(self, name):
        path = os.path.join(SYSTEM_DIR, name)
        if os.path.exists(path):
            if os.path.isdir(path):
                return path

            raise RpcException(errno.EPERM, 'Cannot grant directory {0}'.format(name))

        os.mkdir(path)
        return path

    @description("Returns current .system dataset parameters")
    @returns(h.object())
    def status(self):
        return {
            'id': self.configstore.get('system.dataset.id'),
            'pool': self.configstore.get('system.dataset.pool')
        }


@description("Updates .system dataset configuration")
@accepts(str)
class SystemDatasetConfigure(ProgressTask):
    def __init__(self, dispatcher):
        super(SystemDatasetConfigure, self).__init__(dispatcher)
        self.id = None
        self.src_pool = None
        self.services = []

    @classmethod
    def early_describe(cls):
        return 'Updating .system dataset configuration'

    def describe(self, pool):
        return TaskDescription('Updating .system dataset configuration')

    def verify(self, pool):
        return ['root']

    def run(self, pool):
        def log_errors(err):
            logger.warning('Following errors were encountered during migration:')
            for i in err:
                logger.warning('{0} -> {1}: {2}'.format(*i))

        self.set_progress(0, 'Checking free space on target pool {0}'.format(pool))

        boot_pool = self.dispatcher.configstore.get('system.boot_pool_name')
        status = self.dispatcher.call_sync('system_dataset.status')
        related_services = self.configstore.get('system.dataset.services')
        self.services = [s for s in related_services if self.configstore.get('service.{0}.enable'.format(s))]

        if status['pool'] != pool:
            self.id = self.configstore.get('system.dataset.id')
            self.src_pool = status['pool']
            system_dataset_size = self.dispatcher.call_sync(
                'zfs.dataset.query',
                [('id', '=', '{0}/.system-{1}'.format(status['pool'], self.id))],
                {'select': 'properties.used.parsed', 'single': True}
            )
            if not system_dataset_size:
                raise TaskException(
                    errno.ENOENT,
                    'System dataset not found under {0}/.system-{1}'.format(status['pool'], self.id)
                )

            target_free_space = self.dispatcher.call_sync(
                'zfs.pool.query',
                [('id', '=', pool)],
                {'select': 'properties.free.parsed', 'single': True}
            )

            target_total_size = self.dispatcher.call_sync(
                'zfs.pool.query',
                [('id', '=', pool)],
                {'select': 'properties.size.parsed', 'single': True}
            )

            if not target_free_space or not target_total_size:
                raise TaskException(errno.ENOENT, f'Target pool {pool} not found or not accessible')

            needed_free_space = int(target_total_size * 0.1) + system_dataset_size

            if needed_free_space > target_free_space:
                raise TaskException(
                    errno.ENOSPC,
                    'Not enough space left on pool {0} to move system dataset. Migration needs at least {1}MB'.format(
                        pool,
                        int(needed_free_space) >> 20
                    )
                )

            if pool != boot_pool:
                key_encrypted, password_encrypted = self.dispatcher.call_sync(
                    'volume.query',
                    [('id', '=', pool)],
                    {'single': True, 'select': ('key_encrypted', 'password_encrypted')}
                )
                if key_encrypted or password_encrypted:
                    raise TaskException(errno.EINVAL, 'Cannot migrate .system dataset to an encrypted volume')

            try:
                logger.warning('Services to be restarted: {0}'.format(', '.join(self.services)))
                logger.warning('Migrating system dataset from pool {0} to {1}'.format(self.src_pool, pool))

                tmpath = tempfile.mkdtemp()

                self.set_progress(5, 'Creating a new system dataset on pool {0}'.format(pool))
                create_system_dataset(self.dispatcher, self.id, pool)
                mount_system_dataset(self.dispatcher, self.id, pool, tmpath)

                self.manage_services('stop', 20)

                self.set_progress(30, 'Copying system dataset')

                def copy_error_cb(src, dst, err):
                    if stat.S_ISSOCK(os.lstat(src).st_mode):
                        return

                    if stat.S_ISFIFO(os.lstat(src).st_mode):
                        return

                    log_errors((src, dst, str(err)))
                    raise TaskException(
                        errno.EIO,
                        'System dataset migration failed. Unable to move {0} -> {1} - {2}'.format(src, dst, str(err))
                    )

                copytree(
                    SYSTEM_DIR,
                    tmpath,
                    symlinks=True,
                    error_cb=copy_error_cb,
                    exclude=['freenas-log.db'],
                    badfile_cb=lambda _: True
                )

                self.set_progress(70, 'Copying freenas-log database and switching to the new system dataset')

                self.dispatcher.call_sync('management.stop_logdb')

                try:
                    copytree(
                        os.path.join(SYSTEM_DIR, 'freenas-log.db'),
                        os.path.join(tmpath, 'freenas-log.db'),
                        symlinks=True,
                        badfile_cb=lambda _: True
                    )
                except shutil.Error as err:
                    log_errors(err)
                    raise TaskException(
                        errno.EIO,
                        'System dataset migration failed. Unable to move freenas-log database.'
                    )

                umount_system_dataset(self.dispatcher, self.id, pool)
                umount_system_dataset(self.dispatcher, self.id, self.src_pool)
                mount_system_dataset(self.dispatcher, self.id, pool, SYSTEM_DIR)

            except:
                umount_system_dataset(self.dispatcher, self.id, pool)
                remove_system_dataset(self.dispatcher, self.id, pool)

                mount_system_dataset(self.dispatcher, self.id, self.src_pool, SYSTEM_DIR)

                self.dispatcher.call_sync('management.stop_logdb')
                self.dispatcher.call_sync('management.start_logdb')
                self.manage_services('start')

                if self.src_pool:
                    self.configstore.set('system.dataset.pool', self.src_pool)

                raise

            remove_system_dataset(self.dispatcher, self.id, self.src_pool)

            self.dispatcher.call_sync('management.start_logdb')
            self.configstore.set('system.dataset.pool', pool)

            self.manage_services('start', 90)

    def manage_services(self, operation, start_progress=None):
        states = ('RUNNING', 'STARTING') if operation == 'stop' else ('STOPPING', 'STOPPED')
        services = self.dispatcher.call_sync(
            'service.query',
            [('name', 'in', self.services), ('state', 'in', states)],
            {'select': ('id', 'name')}
        )

        for idx, service in enumerate(services):
            id, name = service
            if start_progress:
                self.set_progress(
                    start_progress + ((idx / len(self.services)) * 10),
                    'Managing dependent services - {0} {1}'.format(operation, name)
                )

            try:
                self.run_subtask_sync('service.manage', id, operation)
            except TaskException as err:
                logger.warning('Failed to {0} {1} service: {2}'.format(operation, name, err))


@private
@description("Imports .system dataset from a volume")
@accepts(str)
class SystemDatasetImport(Task):
    @classmethod
    def early_describe(cls):
        return 'Importing .system dataset from volume'

    def describe(self, pool):
        return TaskDescription('Importing .system dataset from volume {name}', name=pool)

    def verify(self, pool):
        return ['root']

    def run(self, pool):
        if not self.dispatcher.call_sync('zfs.dataset.query', [('pool', '=', pool), ('name', '~', '.system')], {'single': True}):
            raise TaskException(errno.ENOENT, 'System dataset not found on pool {0}'.format(pool))

        status = self.dispatcher.call_sync('system_dataset.status')
        services = self.configstore.get('system.dataset.services')
        restart = [s for s in services if self.configstore.get('service.{0}.enable'.format(s))]

        logger.warning('Services to be restarted: {0}'.format(', '.join(restart)))

        if status['pool'] != pool:
            new_id = import_system_dataset(
                self.dispatcher,
                restart,
                pool,
                status['pool'],
                self.configstore.get('system.dataset.id')
            )

            self.configstore.set('system.dataset.pool', pool)
            self.configstore.set('system.dataset.id', new_id)
            logger.info('New system dataset ID: {0}'.format(new_id))


def _depends():
    return ['VolumePlugin']


def _init(dispatcher, plugin):
    last_sysds_name = ''

    def on_volumes_changed(args):
        if args['operation'] == 'create':
            pass

    def on_datasets_changed(args):
        nonlocal last_sysds_name

        if args['operation'] != 'update':
            return

        for i in args['entities']:
            if '.system-' in i['id'] and i['mountpoint'] == SYSTEM_DIR and i['id'] != last_sysds_name:
                if dispatcher.resource_exists('system-dataset'):
                    dispatcher.update_resource('system-dataset', new_parents=['zfs:{0}'.format(i['id'])])
                else:
                    dispatcher.register_resource(Resource('system-dataset'), parents=['zfs:{0}'.format(i['id'])])

                last_sysds_name = i['id']
                return

    def volume_pre_destroy(args):
        # Evacuate .system dataset from the pool
        if dispatcher.configstore.get('system.dataset.pool') == args['name']:
            dispatcher.call_task_sync('system_dataset.migrate', 'freenas-boot')

        return True

    if not dispatcher.configstore.get('system.dataset.id'):
        dsid = uuid.uuid4().hex[:8]
        dispatcher.configstore.set('system.dataset.id', dsid)
        logger.info('New system dataset ID: {0}'.format(dsid))

    plugin.register_event_handler('volume.changed', on_volumes_changed)
    plugin.register_event_handler('entity-subscriber.zfs.dataset.changed', on_datasets_changed)

    boot_pool = dispatcher.configstore.get('system.boot_pool_name')
    pool = dispatcher.configstore.get('system.dataset.pool')
    dsid = dispatcher.configstore.get('system.dataset.id')

    logger.info('Mounting system dataset')
    try:
        create_system_dataset(dispatcher, dsid, pool)
        mount_system_dataset(dispatcher, dsid, pool, SYSTEM_DIR)
    except Exception as err:
        logger.error(f'Cannot mount system dataset on pool {pool}: {err}')
        logger.error('Reverting back to boot pool')
        create_system_dataset(dispatcher, dsid, boot_pool)
        mount_system_dataset(dispatcher, dsid, boot_pool, SYSTEM_DIR)
        dispatcher.configstore.set('system.dataset.pool', boot_pool)

    link_directories(dispatcher)

    logger.info('Starting log database')
    dispatcher.start_logdb()
    dispatcher.migrate_logdb()
    dispatcher.call_sync('serviced.job.send_signal', 'org.freenas.logd', signal.SIGUSR1)
    dispatcher.logdb_ready = True

    plugin.attach_hook('volume.pre_destroy', volume_pre_destroy)
    plugin.attach_hook('volume.pre_detach', volume_pre_destroy)
    plugin.attach_hook('volume.pre_rename', volume_pre_destroy)
    plugin.register_provider('system_dataset', SystemDatasetProvider)
    plugin.register_task_handler('system_dataset.migrate', SystemDatasetConfigure)
    plugin.register_task_handler('system_dataset.import', SystemDatasetImport)

    plugin.register_hook('system_dataset.pre_detach')
    plugin.register_hook('system_dataset.pre_attach')

