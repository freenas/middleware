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

import enum
import uuid
import os
import errno
import time
import copy
import gevent
import socket
import logging
from cache import CacheStore
from resources import Resource
from datetime import datetime, timedelta
from dateutil.parser import parse as parse_datetime
from task import (
    Provider, Task, ProgressTask, VerifyException, TaskException, TaskWarning, query, TaskDescription,
    TaskAbortException
)
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns, private, generator
from freenas.dispatcher.fd import FileDescriptor
from utils import get_freenas_peer_client, call_task_and_check_state
from freenas.utils import first_or_default, query as q, normalize, human_readable_bytes
from freenas.utils.decorators import throttle
from debug import AttachRPC

logger = logging.getLogger(__name__)

link_cache = None
current_state_cache = None


class ReplicationActionType(enum.Enum):
    SEND_STREAM = 1
    DELETE_SNAPSHOTS = 2
    CLEAR_SNAPSHOTS = 3
    DELETE_DATASET = 4


class ReplicationAction(object):
    def __init__(self, type, localfs, remotefs, **kwargs):
        self.type = type
        self.localfs = localfs
        self.remotefs = remotefs
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getstate__(self):
        d = dict(self.__dict__)
        d['type'] = d['type'].name
        return d


@description('Provides information about replication tasks')
class ReplicationLinkProvider(Provider):
    @query('Replication')
    @generator
    def query(self, filter=None, params=None):
        def extend():
            now = datetime.now()

            for link in link_cache.query(stream=True):

                state = current_state_cache.get(link['id'])
                if not state or (datetime.now() - state['created_at']) > timedelta(minutes=1):
                    self.dispatcher.call_sync('replication.remove_status', link['id'])
                    status = 'STOPPED'
                    if len(link['status']) and link['status'][-1]['status'] == 'FAILED':
                        status = 'FAILED'

                    link['current_state'] = {
                        'created_at': now,
                        'status': status,
                        'progress': 0,
                        'speed': '0B/s'
                    }
                else:
                    link['current_state'] = state

                yield link

        return q.query(extend(), *(filter or []), stream=True, **(params or {}))

    @private
    def sync_query(self, filter=None, params=None):
        def get_latest_links():
            for link in self.datastore.query_stream('replication.links'):
                yield self.dispatcher.call_task_sync('replication.get_latest_link', link['name'])

        return q.query(get_latest_links(), *(filter or []), **(params or {}))

    @private
    def local_query(self, filter=None, params=None):
        return self.datastore.query(
            'replication.links', *(filter or []), **(params or {})
        )

    @private
    def get_one_local(self, name):
        return self.datastore.get_one('replication.links', ('name', '=', name))

    @private
    @accepts(h.ref('Replication'))
    @returns(h.tuple(bool, str))
    def get_replication_state(self, link):
        def check_partner(partner):
            address = self.dispatcher.call_sync(
                'peer.query',
                [('id', '=', link[partner])],
                {'single': True, 'select': 'credentials.address'}
            )
            if not address:
                raise RpcException(errno.ENOENT, 'FreeNAS peer {0} entry have not been found'.format(link[partner]))

            return address

        hostid = self.dispatcher.call_sync('system.info.host_uuid')
        if link['master'] == hostid:
            is_master = True
            remote = check_partner('slave')

        elif link['slave'] == hostid:
            is_master = False
            remote = check_partner('master')

        else:
            raise RpcException(
                errno.EINVAL,
                'Neither master nor slave of replication link is pointing to {0} host'.format(
                    self.dispatcher.call_sync('system.general.get_config')['hostname']
                )
            )

        return is_master, remote

    @private
    def link_cache_put(self, link):
        link_cache.put(link['name'], link)

    @private
    def link_cache_remove(self, name):
        link_cache.remove(name)

    @private
    def put_status(self, id, status):
        current_state_cache.put(id, status)
        self.dispatcher.emit_event('replication.changed', {
            'operation': 'update',
            'ids': [id]
        })

    @private
    def get_status(self, id):
        return current_state_cache.get(id)

    @private
    def remove_status(self, id):
        current_state_cache.remove(id)

    @private
    def local_datasets_from_link(self, link):
        hostid = self.dispatcher.call_sync('system.info.host_uuid')
        is_master = link['master'] == hostid
        datasets = []
        for dataset in iterate_datasets(link['datasets'], is_master, local=True):
            if link['recursive']:
                dependencies = self.dispatcher.call_sync(
                    'zfs.dataset.query',
                    [('name', '~', '^{0}(/|$)'.format(dataset))],
                )

                for dependency in dependencies:
                    if dependency not in datasets:
                        datasets.append(dependency)
            else:
                dependency = self.dispatcher.call_sync('zfs.dataset.query', [('name', '=', dataset)], {'single': True})
                if dependency and dependency not in datasets:
                    datasets.append(dependency)

        return datasets

    @private
    def get_reserved_shares(self, link_name):
        return get_services(self.dispatcher, 'share', 'reserved', link_name)

    @private
    def get_reserved_vms(self, link_name):
        return get_services(self.dispatcher, 'vm', 'reserved', link_name)

    @private
    def get_related_shares(self, link_name):
        return get_services(self.dispatcher, 'share', 'related', link_name)

    @private
    def get_related_vms(self, link_name):
        return get_services(self.dispatcher, 'vm', 'related', link_name)


class ReplicationBaseTask(ProgressTask):
    def get_replication_state(self, link):
        return self.dispatcher.call_sync(
            'replication.get_replication_state',
            self.remove_datastore_timestamps(link)
        )

    def set_datasets_readonly(self, datasets, readonly, client=None):
        for dataset in datasets:
            if client:
                call_task_and_check_state(
                    client,
                    'zfs.update',
                    dataset['name'],
                    {'readonly': {'value': 'on' if readonly else 'off'}}
                )
            else:
                self.run_subtask_sync(
                    'zfs.update',
                    dataset['name'],
                    {'readonly': {'value': 'on' if readonly else 'off'}}
                )

    def set_datasets_mount(self, datasets, mount, recursive=False, client=None):
        caller = client or self.dispatcher
        for dataset in datasets:
            temp_mounted = caller.call_sync(
                'volume.dataset.query',
                [('name', '=', dataset['name'])],
                {'select': 'temp_mountpoint', 'single': True}
            )

            if client:
                if mount and temp_mounted:
                    call_task_and_check_state(
                        client,
                        'zfs.umount',
                        dataset['name'],
                        recursive
                    )

                call_task_and_check_state(
                    client,
                    'zfs.{0}mount'.format('' if mount else 'u'),
                    dataset['name'],
                    recursive
                )
            else:
                if mount and temp_mounted:
                    self.run_subtask_sync(
                        'zfs.umount',
                        dataset['name'],
                        recursive
                    )
                self.run_subtask_sync(
                    'zfs.{0}mount'.format('' if mount else 'u'),
                    dataset['name'],
                    recursive
                )

    def set_datasets_mount_ro(self, link, readonly, client=None):
        rpc_target = client or self.dispatcher
        all_datasets = rpc_target.call_sync('replication.local_datasets_from_link', link)

        parent_datasets = self.get_parent_datasets(all_datasets, link)
        if readonly:
            self.set_datasets_mount(parent_datasets, False, link['recursive'], client)
            self.set_datasets_readonly(all_datasets, True, client)
        else:
            self.set_datasets_readonly(all_datasets, False, client)
            self.set_datasets_mount(parent_datasets, True, link['recursive'], client)

    def remove_datastore_timestamps(self, link):
        out_link = {}
        for key in link:
            if '_at' not in key:
                out_link[key] = link[key]

        return out_link

    def check_datasets_valid(self, link):
        datasets = q.query(
            self.dispatcher.call_sync('replication.local_datasets_from_link', link),
            select='name'
        )
        hostid = self.dispatcher.call_sync('system.info.host_uuid')
        is_master = link['master'] == hostid

        links = self.dispatcher.call_sync('replication.sync_query', [('name', '!=', link['name'])])
        for dataset in datasets:
            for l in links:
                l_datasets = q.query(
                    self.dispatcher.call_sync('replication.local_datasets_from_link', l),
                    select='name'
                )
                l_is_master = l['master'] == hostid

                if dataset in l_datasets:
                    if l['bidirectional'] or link['bidirectional']:
                        raise TaskException(
                            errno.EACCES,
                            'Bi-directional replication cannot share dataset {0} with other replication: {1}.'.format(
                                dataset,
                                l['name'] if link['bidirectional'] else link['name']
                            )
                        )

                    if is_master != l_is_master:
                        raise TaskException(
                            errno.EACCES,
                            'Usage of dataset {0} conflicts with {1} replication. \
                            Datasets cannot be a source and a target of replication at the same time'.format(
                                dataset,
                                l['name']
                            )
                        )
        return True

    def get_parent_datasets(self, datasets, link):
        if not link['recursive']:
            return datasets

        datasets_names = q.query(datasets, select='name')
        len_sorted_datasets = sorted(datasets_names, key=lambda item: (len(item), item))

        parent_datasets = []
        for parent_dataset in len_sorted_datasets:
            parent_datasets.append(parent_dataset)
            for dataset in datasets_names:
                if dataset.startswith(parent_dataset + '/'):
                    len_sorted_datasets.remove(dataset)

        result = []
        for dataset in parent_datasets:
            result.append(q.query(datasets, ('name', '=', dataset), single=True))

        return result


@description("Sets up a replication link")
@accepts(h.all_of(
        h.ref('Replication'),
        h.required(
            'slave', 'master', 'datasets'
        )
    )
)
class ReplicationCreateTask(ReplicationBaseTask):
    @classmethod
    def early_describe(cls):
        return "Creating the replication link"

    def describe(self, link):
        return TaskDescription("Creating the replication link {name}", name=link.get('name', '') or '')

    def verify(self, link):
        if not len(link['datasets']):
            raise VerifyException(errno.ENOENT, 'At least one dataset have to be specified')

        if not link.get('bidirectional'):
            if link.get('replicate_services'):
                raise VerifyException(
                    errno.EINVAL,
                    'Replication of services is available only when bi-directional replication is selected'
                )
            if link.get('auto_recover'):
                raise VerifyException(
                    errno.EINVAL,
                    'Automatic recovery to master is available only when bi-directional replication is selected'
                )
        else:
            for datasets_pair in link['datasets']:
                if datasets_pair['master'] != datasets_pair['slave']:
                    raise VerifyException(
                        errno.EINVAL,
                        'Source and target datasets have to have the same names for bidirectional replication'
                    )

        return ['replication']

    def run(self, link):
        name = link.get('name')
        if name:
            if self.datastore.exists('replication.links', ('name', '=', name)):
                raise TaskException(errno.EEXIST, 'Replication link with name {0} already exists'.format(name))

        normalize(
            link,
            {
                'one_time': False,
                'replicate_services': False,
                'bidirectional': False,
                'auto_recover': False,
                'recursive': False,
                'transport_options': [],
                'snapshot_lifetime': 365 * 24 * 60 * 60,
                'followdelete': False,
                'status': []
            }
        )

        if 'id' not in link:
            link['id'] = str(uuid.uuid4())

        if 'update_date' not in link:
            link['update_date'] = str(datetime.utcnow())

        link['initial_master'] = link['master']

        is_master, remote = self.get_replication_state(link)
        remote_client = get_freenas_peer_client(self, remote)

        if not name:
            def check_name(n):
                c = self.dispatcher.call_sync('replication.local_query', [('name', '=', n)], {'count': True})
                c += remote_client.call_sync('replication.local_query', [('name', '=', n)], {'count': True})
                return c

            cnt = 0
            base = 'replication'
            name = base
            while check_name(name):
                cnt += 1
                name = f'{base}_{cnt - 1}'

            link['name'] = name

        self.check_datasets_valid(link)

        for dataset in iterate_datasets(link['datasets'], is_master):
            if not self.dispatcher.call_sync('zfs.dataset.query', [('name', '=', dataset)], {'count': True}):
                raise TaskException(errno.ENOENT, 'Dataset {0} does not exist'.format(dataset))

        remote_link = remote_client.call_sync('replication.get_one_local', link['name'])
        id = self.datastore.insert('replication.links', link)
        self.dispatcher.call_sync('replication.link_cache_put', link)
        if is_master:
            self.run_subtask_sync('replication.prepare_slave', link)
        if not remote_link:
            call_task_and_check_state(remote_client, 'replication.create', link)
        else:
            if self.remove_datastore_timestamps(remote_link) != self.remove_datastore_timestamps(link):
                raise TaskException(
                    errno.EEXIST,
                    'Replication link {0} already exists on {1}'.format(link['name'], remote)
                )

        self.dispatcher.dispatch_event('replication.changed', {
            'operation': 'create',
            'ids': [id]
        })

        remote_client.disconnect()

        if is_master and link['one_time']:
            self.dispatcher.submit_task('replication.sync', link['id'])

        return id

    def rollback(self, link):
        id = self.datastore.query('replication.links', ('name', '=', link['name']), single=True, select='id')
        if id:
            self.datastore.delete('replication.links', id)
        self.dispatcher.call_sync('replication.link_cache_remove', link['name'])


@private
@description("Ensures slave datasets have been created. Checks if services names are available on slave.")
@accepts(h.ref('Replication'))
class ReplicationPrepareSlaveTask(ReplicationBaseTask):
    @classmethod
    def early_describe(cls):
        return "Preparing slave for replication link"

    def describe(self, link):
        return TaskDescription("Preparing slave for replication link {name}", name=link.get('name') or '')

    def verify(self, link):
        return ['replication']

    def run(self, link):
        is_master, remote = self.get_replication_state(link)
        remote_client = get_freenas_peer_client(self, remote)

        if is_master:
            with self.dispatcher.get_lock('volumes'):
                datasets_to_replicate = self.dispatcher.call_sync('replication.local_datasets_from_link', link)
                root = self.dispatcher.call_sync('volume.get_volumes_root')

                for dataset in datasets_to_replicate:
                    datasets_pair = first_or_default(lambda d: d['master'] == dataset['name'], link['datasets'])
                    if link['replicate_services']:
                        for share in self.dispatcher.call_sync('share.get_dependencies', os.path.join(root, dataset['name']), False, False):
                            remote_share = remote_client.call_sync(
                                'share.query',
                                [('name', '=', share['name'])],
                                {'single': True}
                            )
                            if remote_share:
                                raise TaskException(
                                    errno.EEXIST,
                                    'Share {0} already exists on {1}'.format(share['name'], remote)
                                )

                        dataset_path = self.dispatcher.call_sync('volume.get_dataset_path', dataset['name'])
                        vms = self.dispatcher.call_sync('vm.get_dependencies', dataset_path, False, False)
                        if vms:
                            remote_vm = remote_client.call_sync(
                                'vm.query',
                                [('name', '=', vms[0]['name'])],
                                {'single': True}
                            )
                            if remote_vm:
                                raise TaskException(
                                    errno.EEXIST,
                                    'VM {0} already exists on {1}'.format(vms[0]['name'], remote)
                                )

                    volume_name = dataset['name'].split('/', 1)[0]

                    vol = self.datastore.get_one('volumes', ('id', '=', volume_name))
                    if vol.get('encrypted'):
                        raise TaskException(
                            errno.EINVAL,
                            'Encrypted volumes cannot be source of replication: {0}'.format(volume_name)
                        )

                    if datasets_pair:
                        remote_volume_name = datasets_pair['slave'].split('/', 1)[0]

                        remote_volume = remote_client.call_sync(
                            'volume.query',
                            [('id', '=', remote_volume_name)],
                            {'single': True}
                        )
                        if remote_volume:
                            if remote_volume.get('encrypted'):
                                raise TaskException(
                                    errno.EINVAL,
                                    'Encrypted volumes cannot be target of replication: {0}'.format(
                                        remote_volume_name
                                    )
                                )
                        else:
                            raise TaskException(
                                errno.ENOENT,
                                'Volume {0} not found at slave. Please create it first.'.format(remote_volume_name)
                            )

                        remote_dataset = remote_client.call_sync(
                            'zfs.dataset.query',
                            [('name', '=', datasets_pair['slave'])],
                            {'count': True}
                        )

                        if not remote_dataset:
                            parent_exists = remote_client.call_sync(
                                'zfs.dataset.query',
                                [('id', '=', os.path.dirname(datasets_pair['slave']))],
                                {'count': True}
                            )
                            if parent_exists:
                                call_task_and_check_state(
                                    remote_client,
                                    'volume.dataset.create',
                                    {
                                        'volume': datasets_pair['slave'].split('/', 1)[0],
                                        'id': datasets_pair['slave']
                                    }
                                )
                            else:
                                ds = datasets_pair['slave']
                                raise TaskException(
                                    errno.ENOENT,
                                    f'Neither target dataset {ds} not its parent could be found on the target system'
                                )

                self.set_datasets_mount_ro(link, True, remote_client)

        else:
            call_task_and_check_state(remote_client, 'replication.prepare_slave', link)

        remote_client.disconnect()


@description("Deletes replication link")
@accepts(str, bool)
class ReplicationDeleteTask(ReplicationBaseTask):
    @classmethod
    def early_describe(cls):
        return "Deleting the replication link"

    def describe(self, id, scrub=False):
        name = self.datastore.query('replication.links', ('id', '=', id), select='name', single=True)
        return TaskDescription("Deleting the replication link {name}", name=name or '')

    def verify(self, id, scrub=False):
        return [f'replication:{id}']

    def run(self, id, scrub=False):
        if not self.datastore.exists('replication.links', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Replication link {0} do not exist.'.format(id))

        name = self.datastore.query('replication.links', ('id', '=', id), select='name', single=True)

        link = self.run_subtask_sync('replication.get_latest_link', name)
        remote = None
        is_master = False
        try:
            is_master, remote = self.get_replication_state(link)
        except RpcException:
            pass
        remote_client = None

        if remote:
            try:
                remote_client = get_freenas_peer_client(self, remote)
            except TaskException as e:
                self.add_warning(TaskWarning(
                    e.code,
                    'Remote is unreachable. Delete operation is being performed only locally.'
                ))

            if not is_master:
                for service in ['shares', 'vms']:
                    for reserved_item in self.dispatcher.call_sync('replication.get_reserved_{0}'.format(service), name):
                        self.run_subtask_sync(
                            '{0}.export'.format(service),
                            reserved_item['id']
                        )

                if scrub:
                    with self.dispatcher.get_lock('volumes'):
                        datasets = reversed(self.dispatcher.call_sync('replication.local_datasets_from_link', link))
                        for dataset in datasets:
                            if len(dataset['name'].split('/')) == 1:
                                self.run_subtask_sync('volume.delete', dataset['name'])
                            else:
                                self.run_subtask_sync('volume.dataset.delete', dataset['name'])

        self.datastore.delete('replication.links', link['id'])
        self.dispatcher.call_sync('replication.link_cache_remove', link['name'])

        self.dispatcher.dispatch_event('replication.changed', {
            'operation': 'delete',
            'ids': [link['id']]
        })

        if remote_client:
            if remote_client.call_sync('replication.get_one_local', name):
                call_task_and_check_state(remote_client, 'replication.delete', id)
            remote_client.disconnect()


@description("Update a replication link")
@accepts(str, h.ref('Replication'))
class ReplicationUpdateTask(ReplicationBaseTask):
    @classmethod
    def early_describe(cls):
        return "Updating the replication link"

    def describe(self, id, updated_fields):
        name = self.datastore.query('replication.links', ('id', '=', id), select='name', single=True)
        return TaskDescription("Updating the replication link {name}", name=name or '')

    def verify(self, id, updated_fields):
        if 'datasets' in updated_fields:
            if not len(updated_fields['datasets']):
                raise VerifyException(errno.ENOENT, 'At least one dataset have to be specified')

        return [f'replication:{id}']

    def run(self, id, updated_fields):
        if not self.datastore.exists('replication.links', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Replication link {0} do not exist.'.format(id))

        name = self.datastore.query('replication.links', ('id', '=', id), select='name', single=True)

        link = self.run_subtask_sync('replication.get_latest_link', name)

        if 'status' in updated_fields and link['status'] != updated_fields['status']:
            raise TaskException(errno.EINVAL, 'Replication status is readonly')

        if 'initial_master' in updated_fields:
            if updated_fields['initial_master'] != link['initial_master']:
                raise TaskException(errno.EINVAL, 'Initial master cannot be modified')

        original_link = copy.deepcopy(link)
        old_name = link['name']
        is_master, remote = self.get_replication_state(link)
        remote_available = True
        remote_client = None
        try:
            remote_client = get_freenas_peer_client(self, remote)
        except TaskException as e:
            remote_available = False
            self.add_warning(TaskWarning(
                e.code,
                'Remote {0} is unreachable. Update is being performed only locally.'.format(remote)
            ))

        updated_fields['update_date'] = str(datetime.utcnow())

        if 'datasets' in updated_fields:
            for dataset in iterate_datasets(updated_fields['datasets'], is_master):
                if not self.dispatcher.call_sync('zfs.dataset.query', [('name', '=', dataset)], {'single': True}):
                    raise TaskException(errno.ENOENT, 'Dataset {0} does not exist'.format(dataset))

            if not remote_available:
                raise TaskException(
                    errno.EACCES,
                    'Cannot modify datasets, because remote {0} is unreachable'.format(remote)
                )

        link.update(updated_fields)

        if link['bidirectional']:
            for datasets_pair in link['datasets']:
                if datasets_pair['master'] != datasets_pair['slave']:
                    raise TaskException(
                        errno.EINVAL,
                        'Source and target datasets have to have the same names for bidirectional replication'
                    )

        partners = (link['master'], link['slave'])
        if 'master' in updated_fields:
            if not updated_fields['master'] in partners:
                raise TaskException(
                    errno.EINVAL,
                    'Replication master must be one of replication partners'
                )

            if link['auto_recover']:
                raise TaskException(
                    errno.EINVAL,
                    'Manual role swap is not available when automatic recovery is selected'
                )

        if any(key in updated_fields for key in ['id', 'name', 'master', 'slave']):
            new_is_master, new_remote = self.get_replication_state(link)
            try:
                new_remote_client = get_freenas_peer_client(self, new_remote)
            except TaskException as e:
                raise TaskException(
                    e.code,
                    'New remote {0} is unreachable.'.format(new_remote)
                )
            if remote_available:
                self.run_subtask_sync('replication.delete', id)
                self.run_subtask_sync('replication.create', link)
            else:
                raise TaskException(errno.EACCES, 'Remote {0} is unreachable.'.format(remote))

            new_remote_client.disconnect()

        if any(key in updated_fields for key in ['recursive', 'datasets', 'bidirectional', 'auto_recover']):
            if not remote_available:
                raise TaskException(errno.EACCES, 'Remote {0} is unreachable.'.format(remote))
            self.check_datasets_valid(link)
            call_task_and_check_state(
                remote_client,
                'replication.check_datasets',
                self.remove_datastore_timestamps(link)
            )

        if not link['bidirectional']:
            if link['replicate_services']:
                raise TaskException(
                    errno.EINVAL,
                    'Replication of services is available only when bi-directional replication is selected'
                )
            if link['auto_recover']:
                raise TaskException(
                    errno.EINVAL,
                    'Automatic recovery to master is available only when bi-directional replication is selected'
                )

        if not link['replicate_services']:
            for service in ['shares', 'vms']:
                for reserved_item in self.dispatcher.call_sync('replication.get_reserved_{0}'.format(service), name):
                    self.run_subtask_sync(
                        '{0}.export'.format(service),
                        reserved_item['id']
                    )

        if 'datasets' in updated_fields:
            self.set_datasets_mount_ro(
                original_link,
                False,
                remote_client if is_master else None
            )

            try:
                self.run_subtask_sync('replication.prepare_slave', link)
            except RpcException:
                self.set_datasets_mount_ro(
                    original_link,
                    True,
                    remote_client if is_master else None
                )
                raise

        if remote_available:
            try:
                call_task_and_check_state(
                    remote_client,
                    'replication.update_link',
                    self.remove_datastore_timestamps(link)
                )
            except TaskException as e:
                self.add_warning(TaskWarning(
                    e.code,
                    'Link update at remote side failed: {0}'.format(e.message)
                ))

        self.run_subtask_sync('replication.update_link', link)

        if remote_available and link['replicate_services']:
            try:
                call_task_and_check_state(
                    remote_client,
                    'replication.reserve_services',
                    link['name']
                )
            except TaskException as e:
                self.add_warning(TaskWarning(
                    e.code,
                    'Service reservation failed: {0}'.format(e.message)
                ))

            if 'master' in updated_fields:
                self.run_subtask_sync('replication.role_update', link['id'])

        self.dispatcher.dispatch_event('replication.changed', {
            'operation': 'update',
            'ids': [link['id']]
        })
        if remote_available:
            remote_client.emit_event('replication.changed', {
                'operation': 'update',
                'ids': [link['id']]
            })
            remote_client.disconnect()


@description("Runs replication process based on saved link")
@accepts(str)
class ReplicationSyncTask(ReplicationBaseTask):
    def __init__(self, dispatcher):
        super(ProgressTask, self).__init__(dispatcher)
        self.status = 'FAILED'
        self.message = ''
        self.aborted = False

    @classmethod
    def early_describe(cls):
        return "Synchronizing replication link"

    def describe(self, id):
        name = self.datastore.query('replication.links', ('id', '=', id), select='name', single=True)
        return TaskDescription("Synchronizing replication link {name}", name=name or '')

    def verify(self, id):
        return [f'replication:{id}']

    def run(self, id):
        if not self.datastore.exists('replication.links', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Replication link {0} do not exist.'.format(id))

        name = self.datastore.query('replication.links', ('id', '=', id), select='name', single=True)

        start_time = time.time()
        started_at = datetime.utcnow().isoformat().split('.')[0]
        total_size = 0
        speed = 0
        remote_client = None
        link = self.run_subtask_sync('replication.get_latest_link', name)
        is_master, remote = self.get_replication_state(link)
        try:
            remote_client = get_freenas_peer_client(self, remote)
            if is_master:
                with self.dispatcher.get_lock('volumes'):
                    all_datasets = self.dispatcher.call_sync('replication.local_datasets_from_link', link)
                    parent_datasets = self.get_parent_datasets(all_datasets, link)

                    ds_count = len(parent_datasets)
                    for idx, dataset in enumerate(parent_datasets):
                        if self.aborted:
                            raise TaskAbortException(errno.EINTR, "User invoked task.abort")

                        done = 0

                        def report_progress(prgrs, msg, extra):
                            @throttle(seconds=30)
                            def update_status(p):
                                speed = int(done / (time.time() - start_time))
                                state = {
                                    'task_id': self.environment['ID'],
                                    'created_at': datetime.now(),
                                    'status': 'RUNNING',
                                    'progress': p,
                                    'speed': human_readable_bytes(speed, '/s')
                                }

                                self.dispatcher.call_sync('replication.put_status', link['id'], state)
                                remote_client.call_sync('replication.put_status', link['id'], state)

                            nonlocal done
                            if extra:
                                done += extra

                            update_status(self.chunk_progress(
                                int((idx / ds_count) * 100), int(((idx + 1) / ds_count) * 100),
                                '', prgrs, msg, extra
                            ))

                        datasets_pair = first_or_default(lambda d: d['master'] == dataset['name'], link['datasets'])
                        result = self.run_subtask_sync(
                            'replication.replicate_dataset',
                            datasets_pair['master'],
                            {
                                'remote': remote,
                                'remote_dataset': datasets_pair['slave'],
                                'recursive': link['recursive'],
                                'nomount': True,
                                'lifetime': link['snapshot_lifetime'],
                                'followdelete': link['followdelete']
                            },
                            link['transport_options'],
                            progress_callback=lambda p, m, e=None: report_progress(p, m, e)
                        )

                        total_size += result[1]

                    if link['replicate_services']:
                        call_task_and_check_state(remote_client, 'replication.reserve_services', name)
            else:
                tid = remote_client.submit_task('replication.sync', id)
                while not self.aborted:
                    time.sleep(10)
                    if self.aborted:
                        remote_client.call_sync('task.abort', tid)

                    task_status = remote_client.call_sync('task.status', tid)
                    if task_status['state'] in ('FINISHED', 'FAILED', 'ABORTED'):
                        break

                    status = self.dispatcher.call_sync('replication.get_status', link['id'])
                    if status:
                        self.set_progress(status['progress'], 'Receiving replication stream')

            if not self.aborted:
                self.status = 'SUCCESS'
                self.message = 'Replication completed successfully'

        except TaskAbortException:
            self.status = 'ABORTED'
            self.message = 'Replication aborted by user'
        except TaskException as err:
            self.status = 'FAILED'
            self.message = err.message
            raise
        except BaseException as err:
            self.status = 'FAILED'
            self.message = f'Replication sync failed: {err}'
            raise
        finally:
            if is_master:
                self.dispatcher.call_sync('replication.remove_status', link['id'])
                end_time = time.time()
                if start_time != end_time:
                    speed = int(float(total_size) / float(end_time - start_time))

                status_dict = {
                    'started_at': {'$date': started_at},
                    'ended_at': {'$date': datetime.utcnow().isoformat().split('.')[0]},
                    'status': self.status,
                    'message': self.message,
                    'size': total_size,
                    'speed': speed
                }
                link['status'].append(status_dict)
                link['update_date'] = str(datetime.utcnow())
                self.run_subtask_sync('replication.update_link', link)
                self.dispatcher.dispatch_event('replication.changed', {
                    'operation': 'update',
                    'ids': [link['id']]
                })

                if remote_client:
                    remote_client.call_sync('replication.remove_status', link['id'])
                    call_task_and_check_state(
                        remote_client,
                        'replication.update_link',
                        self.remove_datastore_timestamps(link)
                    )
                    remote_client.emit_event('replication.changed', {
                        'operation': 'update',
                        'ids': [link['id']]
                    })
                    remote_client.disconnect()

                if self.status == 'SUCCESS' and link['one_time']:
                    self.dispatcher.submit_task('replication.delete', id)

    def abort(self):
        self.aborted = True
        self.abort_subtasks()


@private
@description("Creates name reservation for services subject to replication")
@accepts(str)
class ReplicationReserveServicesTask(ReplicationBaseTask):
    @classmethod
    def early_describe(cls):
        return "Reserving services for replication link"

    def describe(self, name):
        return TaskDescription("Reserving services for replication link {name}", name=name)

    def verify(self, name):
        if not self.datastore.exists('replication.links', ('name', '=', name)):
            raise VerifyException(errno.ENOENT, 'Replication link {0} do not exist.'.format(name))

        return []

    def run(self, name):
        if not self.datastore.exists('replication.links', ('name', '=', name)):
            raise TaskException(errno.ENOENT, 'Replication link {0} do not exist.'.format(name))

        service_types = ['shares', 'vms']
        link = self.run_subtask_sync('replication.get_latest_link', name)
        is_master, remote = self.get_replication_state(link)
        remote_client = get_freenas_peer_client(self, remote)

        if is_master:
            call_task_and_check_state(remote_client, 'replication.reserve_services', name)
        else:
            if link['replicate_services']:
                for type in service_types:
                    related_services = remote_client.call_sync('replication.get_related_{0}'.format(type), name)
                    reserved_services = self.dispatcher.call_sync('replication.get_reserved_{0}'.format(type), name)

                    for service in reserved_services:
                        id = service['id']
                        if not first_or_default(lambda s: s['id'] == id, related_services):
                            self.datastore.delete(type, id)
                            self.dispatcher.dispatch_event('{0}.changed'.format(type[:-1]), {
                                'operation': 'delete',
                                'ids': [id]
                            })

                    for service in related_services:
                        service['immutable'] = True
                        service['enabled'] = False
                        id = service['id']
                        if self.datastore.exists(type, ('id', '=', id)):
                            old_service = self.datastore.get_by_id(type, id)
                            if old_service != service:
                                self.datastore.update(type, id, service)
                                self.dispatcher.dispatch_event('{0}.changed'.format(type[:-1]), {
                                    'operation': 'update',
                                    'ids': [id]
                                })
                        else:
                            self.datastore.insert(type, service)
                            self.dispatcher.dispatch_event('{0}.changed'.format(type[:-1]), {
                                'operation': 'create',
                                'ids': [id]
                            })

            else:
                raise TaskException(errno.EINVAL, 'Selected link is not allowed to replicate services')

        remote_client.disconnect()


@private
@description('Creates a snapshot of selected dataset')
@accepts(str, bool, h.one_of(int, None), str, bool)
@returns(str)
class SnapshotDatasetTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating a snapshot of ZFS dataset"

    def describe(self, dataset, recursive, lifetime, prefix='auto', replicable=False):
        return TaskDescription("Creating a snapshot of {name} ZFS dataset", name=dataset)

    def verify(self, dataset, recursive, lifetime, prefix='auto', replicable=False):
        if not self.dispatcher.call_sync('zfs.dataset.query', [('name', '=', dataset)], {'single': True}):
            raise VerifyException(errno.ENOENT, 'Dataset {0} not found'.format(dataset))

        return ['zfs:{0}'.format(dataset)]

    def run(self, dataset, recursive, lifetime, prefix=None, replicable=False):
        if not self.dispatcher.call_sync('zfs.dataset.query', [('name', '=', dataset)], {'single': True}):
            raise TaskException(errno.ENOENT, 'Dataset {0} not found'.format(dataset))

        if not prefix:
            prefix = 'auto'

        snapname = '{0}-{1:%Y%m%d.%H%M}'.format(prefix, datetime.utcnow())

        # XXX
        # calendar_task_name = self.environment.get('calendar_task_name')
        # if calendar_task_name:
        #    params['org.freenas:calendar_task'] = calendar_task_name

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

        self.run_subtask_sync(
            'volume.snapshot.create',
            {
                'dataset': dataset,
                'name': snapname,
                'lifetime': lifetime,
                'replicable': replicable
            },
            recursive
        )


@private
@description('Calculates replication delta between datasets')
class CalculateReplicationDeltaTask(Task):
    @classmethod
    def early_describe(cls):
        return "Calculating replication delta"

    def describe(self, localds, remoteds, snapshots, recursive=False, followdelete=False):
        return TaskDescription(
            "Calculating replication delta between the {name} and the {remoteds}",
            name=localds,
            remoteds=remoteds
        )

    def verify(self, localds, remoteds, snapshots, recursive=False, followdelete=False):
        return ['zfs:{0}'.format(localds)]

    def run(self, localds, remoteds, snapshots_list, recursive=False, followdelete=False):
        datasets = [localds]
        remote_datasets = list(filter(lambda s: '@' not in s['name'], snapshots_list))
        actions = []

        def matches(src, tgt):
            return src['snapshot_name'] == tgt['snapshot_name'] and src['created_at'] == tgt['created_at']

        def match_snapshots(local, remote):
            for i in local:
                match = first_or_default(lambda s: matches(i, s), remote)
                if match:
                    yield i, match

        def convert_snapshot(snap):
            return {
                'name': snap['name'],
                'snapshot_name': snap['snapshot_name'],
                'created_at': int(q.get(snap, 'properties.creation.rawvalue')),
                'txg': int(q.get(snap, 'properties.createtxg.rawvalue')),
                'uuid': q.get(snap, 'properties.org\\.freenas:uuid.value')
            }

        def extend_with_snapshot_name(snap):
            snap['snapshot_name'] = snap['name'].split('@')[-1] if '@' in snap['name'] else None

        for i in snapshots_list:
            extend_with_snapshot_name(i)

        if recursive:
            datasets = list(self.dispatcher.call_sync(
                'zfs.dataset.query',
                [('name', '~', '^{0}(/|$)'.format(localds))],
                {'select': 'name'}
            ))

        for ds in datasets:
            localfs = ds
            remotefs = localfs.replace(localds, remoteds, 1)

            local_snapshots = sorted(
                list(map(
                    convert_snapshot,
                    self.dispatcher.call_sync('zfs.dataset.get_snapshots', localfs)
                )),
                key=lambda x: x['txg']
            )

            remote_snapshots = q.query(
                snapshots_list,
                ('name', '~', '^{0}@'.format(remotefs))
            )

            remote_ds = first_or_default(lambda s: s['name'] == remotefs, snapshots_list)
            snapshots = local_snapshots[:]
            found = None

            if remote_ds and remote_ds.get('resume_token'):
                # There's unfinished replication
                token_info = self.dispatcher.call_sync(
                    'zfs.dataset.describe_resume_token',
                    remote_ds.get('resume_token')
                )

                actions.append(ReplicationAction(
                    ReplicationActionType.SEND_STREAM,
                    localfs,
                    remotefs,
                    resume=True,
                    incremental=False,
                    token=remote_ds.get('resume_token'),
                    bytes=token_info['bytes'],
                    snapshot=token_info['toname'].split('@')[-1]
                ))

                found = first_or_default(lambda s: s['name'] == token_info['toname'], local_snapshots)

            if remote_snapshots or found:
                # Find out the last common snapshot.
                if not found:
                    pairs = list(match_snapshots(local_snapshots, remote_snapshots))
                    if pairs:
                        pairs.sort(key=lambda p: p[0]['created_at'], reverse=True)
                        found, _ = first_or_default(None, pairs)

                if found:
                    if followdelete:
                        delete = []
                        for snap in remote_snapshots:
                            rsnap = snap['snapshot_name']
                            if not first_or_default(lambda s: s['snapshot_name'] == rsnap, local_snapshots):
                                delete.append(rsnap)

                        if delete:
                            actions.append(ReplicationAction(
                                ReplicationActionType.DELETE_SNAPSHOTS,
                                localfs,
                                remotefs,
                                snapshots=delete
                            ))

                    index = local_snapshots.index(found)

                    for idx in range(index + 1, len(local_snapshots)):
                        actions.append(ReplicationAction(
                            ReplicationActionType.SEND_STREAM,
                            localfs,
                            remotefs,
                            incremental=True,
                            anchor=local_snapshots[idx - 1]['snapshot_name'],
                            snapshot=local_snapshots[idx]['snapshot_name']
                        ))
                else:
                    actions.append(ReplicationAction(
                        ReplicationActionType.CLEAR_SNAPSHOTS,
                        localfs,
                        remotefs,
                        snapshots=[snap['snapshot_name'] for snap in remote_snapshots]
                    ))

                    for idx in range(0, len(snapshots)):
                        actions.append(ReplicationAction(
                            ReplicationActionType.SEND_STREAM,
                            localfs,
                            remotefs,
                            incremental=idx > 0,
                            anchor=snapshots[idx - 1]['snapshot_name'] if idx > 0 else None,
                            snapshot=snapshots[idx]['snapshot_name']
                        ))
            else:
                logger.info('New dataset {0} -> {1}'.format(localfs, remotefs))
                for idx in range(0, len(snapshots)):
                    actions.append(ReplicationAction(
                        ReplicationActionType.SEND_STREAM,
                        localfs,
                        remotefs,
                        incremental=idx > 0,
                        anchor=snapshots[idx - 1]['snapshot_name'] if idx > 0 else None,
                        snapshot=snapshots[idx]['snapshot_name']
                    ))

        for rds in remote_datasets:
            remotefs = rds['name']
            localfs = remotefs.replace(remoteds, localds, 1)

            if localfs not in datasets:
                actions.append(ReplicationAction(
                    ReplicationActionType.DELETE_DATASET,
                    localfs,
                    remotefs
                ))

        total_send_size = 0

        for action in actions:
            if action.type == ReplicationActionType.SEND_STREAM:
                if getattr(action, 'resume', False):
                    size = action.bytes
                else:
                    size = self.dispatcher.call_sync(
                        'zfs.dataset.estimate_send_size',
                        action.localfs,
                        action.snapshot,
                        getattr(action, 'anchor', None)
                    )

                action.send_size = size
                total_send_size += size

        return actions, total_send_size


@accepts(str, h.ref('ReplicationOptions'), h.one_of(None, h.array(h.ref('ReplicationTransportOption'))), bool)
@description("Runs a dataset replication with the specified arguments")
class ReplicateDatasetTask(ProgressTask):
    def __init__(self, dispatcher):
        super(ReplicateDatasetTask, self).__init__(dispatcher)
        self.rd_fd = None
        self.wr_fd = None
        self.aborted = False

    @classmethod
    def early_describe(cls):
        return "Replicating dataset"

    def describe(self, localds, options, transport_plugins=None, dry_run=False):
        return TaskDescription("Replicating dataset {name}", name=localds)

    def verify(self, localds, options, transport_plugins=None, dry_run=False):
        return ['zfs:{0}'.format(localds)]

    def run(self, localds, options, transport_plugins=None, dry_run=False):
        remote = options.get('remote')
        remoteds = options['remote_dataset']
        followdelete = options.get('followdelete', False)
        recursive = options.get('recursive', False)
        lifetime = options.get('lifetime', 365 * 24 * 60 * 60)
        force = options.get('force', True)
        peer = options.get('peer')
        nomount = options.get('nomount', False)

        if not self.aborted:
            self.run_subtask_sync(
                'volume.snapshot_dataset',
                localds,
                True,
                lifetime,
                'repl',
                True
            )
        else:
            raise TaskAbortException(errno.EINTR, "User invoked task.abort")

        if peer:
            remote = self.dispatcher.call_sync(
                'peer.query',
                [('type', '=', 'freenas'), ('id', '=', peer)],
                {'single': True, 'select': 'credentials.address'}
            )

            if not remote:
                raise TaskException(errno.ENOENT, 'Peer {0} not found'.format(peer))

        if not remote:
            raise TaskException(errno.EINVAL, 'Remote host is not specified')

        remote_client = get_freenas_peer_client(self, remote)

        def is_replicated(snapshot):
            if q.get(snapshot, 'properties.org\\.freenas:replicable.value') != 'yes':
                # Snapshot is not subject to replication
                return False

            return True

        self.set_progress(0, 'Reading replication state from remote side...')

        remote_client.call_sync('zfs.dataset.refresh_resume_tokens')
        remote_datasets = remote_client.call_sync(
            'zfs.dataset.query',
            [('id', '~', '^{0}(/|$)'.format(remoteds))]
        )

        remote_snapshots = remote_client.call_sync(
            'zfs.snapshot.query',
            [('id', '~', '^{0}(/|$|@)'.format(remoteds))]
        )

        remote_data = []

        for i in remote_datasets:
            if i['name'].endswith('/%recv'):
                continue

            token = q.get(i, 'properties.receive_resume_token.value')
            if not token:
                recv_dataset = first_or_default(lambda d: d['name'] == f'{i["name"]}/%recv', remote_datasets)
                token = q.get(recv_dataset, 'properties.receive_resume_token.value')

            remote_data.append({
                'name': i['name'],
                'created_at': int(q.get(i, 'properties.creation.rawvalue')),
                'uuid': q.get(i, 'properties.org\\.freenas:uuid.value'),
                'resume_token': token
            })

        for i in remote_snapshots:
            if not is_replicated(i):
                continue

            remote_data.append({
                'name': i['name'],
                'created_at': int(q.get(i, 'properties.creation.rawvalue')),
                'uuid': q.get(i, 'properties.org\\.freenas:uuid.value'),
                'resume_token': None
            })

        if not self.aborted:
            actions, send_size = self.run_subtask_sync(
                'replication.calculate_delta',
                localds,
                remoteds,
                remote_data,
                recursive,
                followdelete
            )
        else:
            raise TaskAbortException(errno.EINTR, "User invoked task.abort")

        if dry_run:
            return actions, send_size

        # 2nd pass - actual send
        progress = 0
        done = 0
        actions_len = len(actions)

        for idx, action in enumerate(actions):
            def get_progress(delta=None):
                nonlocal progress, done, idx
                if delta:
                    done += delta

                progress = ((idx / actions_len) * 100) + ((1 / actions_len) * 100 * (done / (send_size or 1)))
                if progress > 100:
                    progress = 100

                return progress

            if self.aborted:
                raise TaskAbortException(errno.EINTR, "User invoked task.abort")

            if action['type'] in (ReplicationActionType.DELETE_SNAPSHOTS.name, ReplicationActionType.CLEAR_SNAPSHOTS.name):
                self.set_progress(get_progress(), 'Removing snapshots on remote dataset {0}'.format(action['remotefs']))
                # Remove snapshots on remote side
                result = remote_client.call_task_sync(
                    'zfs.delete_multiple_snapshots',
                    action['remotefs'],
                    action.get('snapshots')
                )

                if result['state'] != 'FINISHED':
                    raise TaskException(errno.EFAULT, 'Failed to destroy snapshots on remote end: {0}'.format(
                        result['error']['message']
                    ))

            if action['type'] == ReplicationActionType.SEND_STREAM.name:
                self.rd_fd, self.wr_fd = os.pipe()
                fromsnap = action['anchor'] if 'anchor' in action else None

                if action.get('resume'):
                    send_task = self.run_subtask(
                        'zfs.send_resume',
                        action['token'],
                        FileDescriptor(self.wr_fd)
                    )
                else:
                    send_task = self.run_subtask(
                        'zfs.send',
                        action['localfs'],
                        fromsnap,
                        action['snapshot'],
                        FileDescriptor(self.wr_fd)
                    )

                self.join_subtasks(
                    send_task,
                    self.run_subtask(
                        'replication.transport.send',
                        FileDescriptor(self.rd_fd),
                        {
                            'client_address': remote,
                            'transport_plugins': transport_plugins,
                            'receive_properties': {
                                'name': action['remotefs'],
                                'force': force,
                                'nomount': nomount,
                                'props': {'mountpoint': None}
                            },
                            'estimated_size': send_size or 1
                        },
                        progress_callback=lambda p, m, e=None: self.set_progress(
                            get_progress(e),
                            'Sending {0} stream of snapshot {1}@{2} - {3}% - speed {4}'.format(
                                'incremental' if action['incremental'] else 'full',
                                action['localfs'],
                                action['snapshot'],
                                int(p),
                                human_readable_bytes(e, '/s')
                            ),
                            extra=e
                        )
                    )
                )

            if action['type'] == ReplicationActionType.DELETE_DATASET.name:
                self.set_progress(get_progress(), 'Removing remote dataset {0}'.format(action['remotefs']))
                result = remote_client.call_task_sync(
                    'zfs.destroy',
                    action['remotefs']
                )

                if result['state'] != 'FINISHED':
                    raise TaskException(errno.EFAULT, 'Failed to destroy dataset {0} on remote end: {1}'.format(
                        action['remotefs'],
                        result['error']['message']
                    ))

        remote_client.disconnect()

        subtasks = []
        for i in set(i['localfs'] for i in actions):
            subtasks.append(self.run_subtask('zfs.update', i, {
                'org.freenas:last_replicated_by': {'value': self.environment.get('CALENDAR_TASK_NAME', '<none>')},
                'org.freenas:last_replicated_at': {'value': int(time.time())}
            }))

        return actions, send_size

    def abort(self):
        self.aborted = True
        self.abort_subtasks()


@private
@description("Returns latest replication link of given name")
@accepts(str)
@returns(h.ref('Replication'))
class ReplicationGetLatestLinkTask(ReplicationBaseTask):
    @classmethod
    def early_describe(cls):
        return "Fetching latest replication link"

    def describe(self, name):
        return TaskDescription("Fetching latest replication link {name}", name=name)

    def verify(self, name):
        if not self.datastore.exists('replication.links', ('name', '=', name)):
            raise VerifyException(errno.ENOENT, 'Replication link {0} do not exist.'.format(name))

        return []

    def run(self, name):
        if not self.datastore.exists('replication.links', ('name', '=', name)):
            raise TaskException(errno.ENOENT, 'Replication link {0} do not exist.'.format(name))

        local_link = self.dispatcher.call_sync('replication.get_one_local', name)
        client = None
        remote_link = None
        latest_link = local_link

        try:
            is_master, remote = self.get_replication_state(local_link)
        except RpcException:
            return local_link

        try:
            client = get_freenas_peer_client(self, remote)
            remote_link = client.call_sync('replication.get_one_local', name)
        except RpcException:
            pass

        if remote_link:
            local_update_date = parse_datetime(local_link['update_date'])
            remote_update_date = parse_datetime(remote_link['update_date'])

            if local_update_date > remote_update_date:
                call_task_and_check_state(client, 'replication.update_link', self.remove_datastore_timestamps(local_link))
                client.emit_event('replication.changed', {
                    'operation': 'update',
                    'ids': [local_link['id']]
                })
            elif local_update_date < remote_update_date:
                self.run_subtask_sync('replication.update_link', remote_link)
                latest_link = remote_link
                self.dispatcher.dispatch_event('replication.changed', {
                    'operation': 'update',
                    'ids': [remote_link['id']]
                })

        if client:
            client.disconnect()
        return latest_link


@private
@description("Updates local replication link entry if provided entry is newer")
@accepts(h.ref('Replication'))
class ReplicationUpdateLinkTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating replication link"

    def describe(self, link):
        return TaskDescription("Updating replication link {name}", name=link['name'])

    def verify(self, link):
        if not self.datastore.exists('replication.links', ('name', '=', link['name'])):
            raise VerifyException(errno.ENOENT, 'Replication link {0} do not exist.'.format(link['name']))

        return []

    def run(self, link):
        if not self.datastore.exists('replication.links', ('name', '=', link['name'])):
            raise TaskException(errno.ENOENT, 'Replication link {0} do not exist.'.format(link['name']))

        local_link = self.dispatcher.call_sync('replication.get_one_local', link['name'])
        local_partners = (local_link['master'], local_link['slave'])
        for partner in local_partners:
            if partner not in (link['master'], link['slave']):
                raise TaskException(
                    errno.EINVAL,
                    'One of remote link partners {0} do not match local link partners {1}, {2}'.format(
                        partner,
                        *local_partners
                    )
                )

        if parse_datetime(local_link['update_date']) < parse_datetime(link['update_date']):
            self.datastore.update('replication.links', link['id'], link)
            self.dispatcher.call_sync('replication.link_cache_put', link)


@private
@description("Performs synchronization of actual role (master/slave) with replication link state")
@accepts(str)
class ReplicationRoleUpdateTask(ReplicationBaseTask):
    @classmethod
    def early_describe(cls):
        return "Synchronizing replication link role with it's desired state"

    def describe(self, id):
        name = self.datastore.query('replication.links', ('id', '=', id), select='name', single=True)
        return TaskDescription("Synchronizing replication link {name} role with it's desired state", name=name or '')

    def verify(self, id):
        return [f'replication:{id}']

    def run(self, id):
        if not self.datastore.exists('replication.links', ('id', '=', id)):
            raise TaskException(errno.ENOENT, f'Replication link {id} do not exist.')

        name = self.datastore.query('replication.links', ('id', '=', id), select='name', single=True)

        link = self.run_subtask_sync('replication.get_latest_link', name)
        if not link['bidirectional']:
            return

        is_master, remote = self.get_replication_state(link)
        datasets = self.dispatcher.call_sync('replication.local_datasets_from_link', link)
        current_readonly = self.dispatcher.call_sync(
            'zfs.dataset.query',
            [('name', '=', datasets[0]['name'])],
            {'single': True, 'select': 'properties.readonly.value'}
        )
        current_readonly = True if current_readonly == 'on' else False

        if (is_master and current_readonly) or (not is_master and not current_readonly):
            self.set_datasets_mount_ro(link, not current_readonly)
            if current_readonly:
                relation_type = 'reserved'
                action_type = False
            else:
                relation_type = 'related'
                action_type = True

            for service in ['shares', 'vms']:
                items = self.dispatcher.call_sync(
                    'replication.get_{0}_{1}'.format(relation_type, service),
                    name,
                    timeout=300
                )
                for reserved_item in items:
                    self.run_subtask_sync(
                        '{0}.immutable.set'.format(service[:-1]),
                        reserved_item['id'],
                        action_type
                    )


@private
@description("Checks if provided replication link would not conflict with other links")
@accepts(h.ref('Replication'))
class ReplicationCheckDatasetsTask(ReplicationBaseTask):
    @classmethod
    def early_describe(cls):
        return "Checking for conflicts with replication link"

    def describe(self, link):
        return TaskDescription("Checking for conflicts with replication link {name}", name=link['name'])

    def verify(self, link):
        if not self.datastore.exists('replication.links', ('name', '=', link['name'])):
            raise VerifyException(errno.ENOENT, 'Replication link {0} do not exist.'.format(link['name']))

        return [f'replication:{link["id"]}']

    def run(self, link):
        if not self.datastore.exists('replication.links', ('name', '=', link['name'])):
            raise TaskException(errno.ENOENT, 'Replication link {0} do not exist.'.format(link['name']))

        self.check_datasets_valid(link)


@description("Deletes replication status history")
@accepts(str)
class ReplicationCleanHistoryTask(ReplicationBaseTask):
    @classmethod
    def early_describe(cls):
        return "Deleting replication status history"

    def describe(self, id):
        link = self.datastore.get_by_id('replication.links', id)
        return TaskDescription("Deleting replication {name} status history", name=link['name'] if link else id)

    def verify(self, id):
        return [f'replication:{id}']

    def run(self, id):
        if not self.datastore.exists('replication.links', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Replication link {0} do not exist.'.format(id))

        link = self.datastore.get_by_id('replication.links', id)
        link['status'] = []
        link['update_date'] = str(datetime.utcnow())

        _, remote = self.get_replication_state(link)
        remote_client = get_freenas_peer_client(self, remote)

        self.run_subtask_sync('replication.update_link', link)
        self.dispatcher.dispatch_event('replication.changed', {
            'operation': 'update',
            'ids': [link['id']]
        })

        if remote_client:
            call_task_and_check_state(
                remote_client,
                'replication.update_link',
                self.remove_datastore_timestamps(link)
            )
            remote_client.emit_event('replication.changed', {
                'operation': 'update',
                'ids': [link['id']]
            })
            remote_client.disconnect()


def get_services(dispatcher, service, relation, link_name):
    services = []
    link = dispatcher.call_task_sync('replication.get_latest_link', link_name)
    datasets = dispatcher.call_sync('replication.local_datasets_from_link', link)
    for dataset in datasets:
        dataset_path = dispatcher.call_sync('volume.get_dataset_path', dataset['name'])
        s = dispatcher.call_sync('{0}.get_dependencies'.format(service), dataset_path, False, False)
        if relation == 'reserved':
            s = q.query(s, ('immutable', '=', True))
        services.extend(s)

    return services


def get_replication_resources(dispatcher, link):
    resources = ['replication']
    datasets = q.query(dispatcher.call_sync('replication.local_datasets_from_link', link), select='name')
    for dataset in datasets:
        resources.append(f'zfs:{dataset}')
    return resources


def iterate_datasets(datasets, is_master, local=True):
    for d in datasets:
        if is_master and local:
            yield d['master']
        else:
            yield d['slave']


def collect_debug(dispatcher):
    yield AttachRPC('replication-query', 'replication.query')


def _depends():
    return ['NetworkPlugin', 'ServiceManagePlugin', 'ZfsPlugin', 'ReplicationTransportPlugin']


def _init(dispatcher, plugin):
    global link_cache, current_state_cache
    link_cache = CacheStore()
    current_state_cache = CacheStore()

    plugin.register_schema_definition('ReplicationOptions', {
        'type': 'object',
        'properties': {
            'remote': {'type': 'string'},
            'peer': {'type': 'string'},
            'remote_dataset': {'type': 'string'},
            'followdelete': {'type': 'boolean'},
            'lifetime': {'type': ['number', 'null']},
            'recursive': {'type': 'boolean'},
            'force': {'type': 'boolean'},
            'nomount': {'type': 'boolean'}
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('Replication', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'master': {'type': 'string'},
            'slave': {'type': 'string'},
            'initial_master': {'type': 'string'},
            'update_date': {'type': 'string'},
            'datasets': {
                'type': 'array',
                'items': {'$ref': 'DatasetsReplicationPair'}
            },
            'bidirectional': {'type': 'boolean'},
            'auto_recover': {'type': 'boolean'},
            'replicate_services': {'type': 'boolean'},
            'one_time': {'type': 'boolean'},
            'recursive': {'type': 'boolean'},
            'status': {
                'type': 'array',
                'items': {'$ref': 'ReplicationStatus'}
            },
            'current_state': {'$ref': 'ReplicationRuntimeState'},
            'transport_options': {
                'type': 'array',
                'items': {'$ref': 'ReplicationTransportOption'}
            },
            'snapshot_lifetime': {'type': 'number'},
            'followdelete': {'type': 'boolean'}
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('ReplicationStatus', {
        'type': 'object',
        'properties': {
            'started_at': {'type': 'datetime'},
            'ended_at': {'type': 'datetime'},
            'status': {'type': 'string'},
            'message': {'type': 'string'},
            'size': {'type': 'number'},
            'speed': {'type': 'number'},
            'task_id': {'type': 'integer'}
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('ReplicationRuntimeState', {
        'type': 'object',
        'properties': {
            'created_at': {'type': 'datetime'},
            'status': {
                'type': 'string',
                'enum': ['RUNNING', 'STOPPED', 'FAILED', 'ABORTED']
            },
            'progress': {'type': 'number'},
            'speed': {'type': 'string'}
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('SnapshotInfo', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'name': {'type': 'string'},
            'created_at': {'type': 'string'},
            'uuid': {'type': ['string', 'null']},
            'type': {'$ref': 'SnapshotInfoType'}
        }
    })

    plugin.register_schema_definition('DatasetsReplicationPair', {
        'type': 'object',
        'properties': {
            'master': {'type': 'string'},
            'slave': {'type': 'string'}
        },
        'additionalProperties': False
    })

    plugin.register_schema_definition('SnapshotInfoType', {
        'type': 'string',
        'enum': ['FILESYSTEM', 'VOLUME']
    })

    plugin.register_schema_definition('CompressReplicationTransportOption', {
        'type': 'object',
        'properties': {
            '%type': {'enum': ['CompressReplicationTransportOption']},
            'level': {'$ref': 'CompressPluginLevel'}
        },
        'additionalProperties': False
    })

    plugin.register_schema_definition('EncryptReplicationTransportOption', {
        'type': 'object',
        'properties': {
            '%type': {'enum': ['EncryptReplicationTransportOption']},
            'type': {'$ref': 'EncryptPluginType'}
        },
        'additionalProperties': False
    })

    plugin.register_schema_definition('ThrottleReplicationTransportOption', {
        'type': 'object',
        'properties': {
            '%type': {'enum': ['ThrottleReplicationTransportOption']},
            'buffer_size': {'type': 'integer'}
        },
        'additionalProperties': False
    })

    # Register transport plugin schema
    plugin.register_schema_definition('ReplicationTransportOption', {
        'discriminator': '%type',
        'oneOf': [
            {'$ref': '{0}ReplicationTransportOption'.format(name.title())} for name in dispatcher.call_sync(
                'replication.transport.plugin_types'
            )
        ]
    })

    dispatcher.register_resource(Resource('replication'))
    plugin.register_provider('replication', ReplicationLinkProvider)
    plugin.register_task_handler('volume.snapshot_dataset', SnapshotDatasetTask)
    plugin.register_task_handler('replication.calculate_delta', CalculateReplicationDeltaTask)
    plugin.register_task_handler('replication.replicate_dataset', ReplicateDatasetTask)
    plugin.register_task_handler('replication.get_latest_link', ReplicationGetLatestLinkTask)
    plugin.register_task_handler('replication.update_link', ReplicationUpdateLinkTask)
    plugin.register_task_handler('replication.create', ReplicationCreateTask)
    plugin.register_task_handler('replication.prepare_slave', ReplicationPrepareSlaveTask)
    plugin.register_task_handler('replication.update', ReplicationUpdateTask)
    plugin.register_task_handler('replication.sync', ReplicationSyncTask)
    plugin.register_task_handler('replication.role_update', ReplicationRoleUpdateTask)
    plugin.register_task_handler('replication.reserve_services', ReplicationReserveServicesTask)
    plugin.register_task_handler('replication.delete', ReplicationDeleteTask)
    plugin.register_task_handler('replication.check_datasets', ReplicationCheckDatasetsTask)
    plugin.register_task_handler('replication.clean_history', ReplicationCleanHistoryTask)

    plugin.register_event_type('replication.changed')

    def on_replication_change(args):
        if args['operation'] == 'delete':
            return

        for i in args['ids']:
            link = dispatcher.call_sync('replication.local_query', [('id', '=', i)], {'single': True})
            if link:
                if link['bidirectional']:
                    dispatcher.call_task_sync('replication.role_update', i)

    def update_link_cache(args):
        sshd_service = dispatcher.call_sync('service.query', [('name', '=', 'sshd')], {'single': True})
        dispatcher.test_or_wait_for_event(
            'service.changed',
            lambda ar:
                sshd_service['id'] in ar['ids'] and
                dispatcher.call_sync(
                    'service.query',
                    [('name', '=', 'sshd')],
                    {'select': 'state', 'single': True}
                ) == 'RUNNING',
            lambda: sshd_service['state'] == 'RUNNING',
            timeout=30
        )

        # Query, if possible, performs sync of replication links cache at both ends of each link
        links = dispatcher.call_sync('replication.sync_query')
        # And retry failed ones over encrypted link
        resync = False
        for link in links:
            try:
                if link['replicate_services']:
                    dispatcher.call_task_sync('replication.reserve_services', link['name'])
                status = link.get('status')
                if len(status):
                    last_status = status[-1]
                else:
                    continue

                hostid = dispatcher.call_sync('system.info.host_uuid')
                is_master = link['master'] == hostid
                recover = link['auto_recover'] and link['initial_master'] != link['master'] and not is_master
                if (last_status and last_status['status'] == 'FAILED') and recover:
                    dispatcher.call_task_sync(
                        'replication.sync',
                        link['id']
                    )
                if recover:
                    link['update_date'] = str(datetime.utcnow())
                    link['master'] = link['initial_master']
                    dispatcher.call_task_sync('replication.update_link', link)
                    dispatcher.dispatch_event('replication.changed', {
                        'operation': 'update',
                        'ids': [link['id']]
                    })
                    resync = True
            except TaskException:
                pass

            if resync:
                dispatcher.call_sync('replication.sync_query')

    def recover_replications():
        interval = dispatcher.configstore.get('replication.auto_recovery_ping_interval')
        while True:
            gevent.sleep(interval)
            for link in dispatcher.call_sync('replication.local_query', [('auto_recover', '=', True)]):
                is_master, remote = dispatcher.call_sync('replication.get_replication_state', link)
                if is_master:
                    continue

                peer_ssh_port = dispatcher.call_sync(
                    'peer.query',
                    [('type', '=', 'freenas'), ('credentials.address', '=', remote)],
                    {'single': True, 'select': 'credentials.port'}
                )
                if not peer_ssh_port:
                    continue

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect((remote, peer_ssh_port))
                except socket.error:
                    link['update_date'] = str(datetime.utcnow())
                    old_master = link['master']
                    link['master'] = link['slave']
                    link['slave'] = old_master
                    dispatcher.call_task_sync('replication.update_link', link)
                    dispatcher.dispatch_event('replication.changed', {
                        'operation': 'update',
                        'ids': [link['id']]
                    })
                s.close()

    plugin.register_event_handler('replication.changed', on_replication_change)
    plugin.register_event_handler('network.changed', update_link_cache)
    for link in dispatcher.datastore.query_stream('replication.links'):
        dispatcher.call_sync('replication.link_cache_put', link)

    gevent.spawn(recover_replications)

    dispatcher.track_resources(
        'replication.query',
        'entity-subscriber.replication.changed',
        lambda id: f'replication:{id}',
        lambda link: get_replication_resources(dispatcher, link)
    )

    plugin.register_debug_hook(collect_debug)
