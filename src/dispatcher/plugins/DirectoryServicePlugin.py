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

import errno
import logging
from datastore.config import ConfigNode
from freenas.dispatcher import Password
from freenas.dispatcher.rpc import RpcException, accepts, returns, SchemaHelper as h, generator
from task import Provider, Task, TaskDescription, TaskException, query
from freenas.utils.lazy import lazy
from freenas.utils.password import unpassword
from freenas.utils import normalize, query as q
from debug import AttachRPC


logger = logging.getLogger('DirectoryServicePlugin')


class DirectoryServiceProvider(Provider):
    def get_config(self):
        return ConfigNode('directory', self.configstore).__getstate__()


class DirectoryProvider(Provider):
    @query('Directory')
    @generator
    def query(self, filter=None, params=None):
        def extend(directory):
            for k, v in directory['parameters'].items():
                if k == 'password':
                    directory['parameters'][k] = Password(v)

            directory['status'] = lazy(self.dispatcher.call_sync, 'dscached.management.get_status', directory['id'])
            return directory

        return q.query(
            self.datastore.query_stream('directories', callback=extend),
            *(filter or []),
            stream=True,
            **(params or {})
        )


@accepts(h.ref('DirectoryserviceConfig'))
class DirectoryServicesConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating directory services settings"

    def describe(self, updated_params):
        return TaskDescription(self.early_describe())

    def verify(self, updated_params):
        return ['system']

    def run(self, updated_params):
        node = ConfigNode('directory', self.configstore)
        node.update(updated_params)

        self.dispatcher.emit_event('directoryservice.changed', {
            'operation': 'update'
        })

        try:
            self.dispatcher.call_sync('dscached.management.reload_config')
            self.dispatcher.call_sync('dscached.management.flush_cache')
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure directory services: {0}'.format(str(e)))


@accepts()
class DirectoryServiceFlushCacheTask(Task):
    @classmethod
    def early_describe(cls):
        return "Flushing directory services cache"

    def describe(self, updated_params):
        return TaskDescription(self.early_describe())

    def verify(self, updated_params):
        return ['system']

    def run(self, updated_params):
        try:
            self.dispatcher.call_sync('dscached.management.flush_cache')
        except RpcException as e:
            raise TaskException(e.code, f'Cannot flush cache: {e}')


@accepts(
    h.ref('Directory'),
    h.required('name', 'type'),
    h.forbidden('immutable')
)
@returns(str)
class DirectoryServiceCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating a directory"

    def describe(self, directory):
        return TaskDescription("Creating directory {name}", name=directory.get('name', ''))

    def verify(self, directory):
        return ['system']

    def run(self, directory):
        try:
            params = self.dispatcher.call_sync(
                'dscached.management.normalize_parameters',
                directory['type'],
                directory.get('parameters', {})
            )
        except RpcException as err:
            raise TaskException(err.code, err.message)

        if self.datastore.exists('directories', ('name', '=', directory['name'])):
            raise TaskException(errno.EEXIST, 'Directory {0} already exists'.format(directory['name']))

        normalize(directory, {
            'enabled': False,
            'enumerate': True,
            'immutable': False,
            'uid_range': None,
            'gid_range': None
        })

        # Replace passed in params with normalized ones
        directory['parameters'] = params

        for k, v in directory['parameters'].items():
            if k == 'password':
                directory['parameters'][k] = unpassword(v)

        if directory['type'] == 'winbind':
            normalize(directory, {
                'uid_range': [100000, 999999],
                'gid_range': [100000, 999999]
            })

            smb = self.dispatcher.call_sync('service.query', [('name', '=', 'smb')], {"single": True})
            if not q.get(smb, 'config.enable'):
                q.set(smb, 'config.enable', True)
                self.run_subtask_sync('service.update', smb['id'], smb)

        self.id = self.datastore.insert('directories', directory)
        self.dispatcher.call_sync('dscached.management.configure_directory', self.id)

        node = ConfigNode('directory', self.configstore)
        node['search_order'] = node['search_order'].value + [directory['name']]
        self.dispatcher.call_sync('dscached.management.reload_config')
        self.dispatcher.dispatch_event('directory.changed', {
            'operation': 'create',
            'ids': [self.id]
        })

        return self.id

    def rollback(self, directory):
        if hasattr(self, 'id'):
            self.datastore.delete('directories', self.id)


@accepts(str, h.ref('Directory'))
class DirectoryServiceUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating a directory"

    def describe(self, id, updated_params):
        directory = self.datastore.get_by_id('directories', id)
        return TaskDescription("Updating directory {name}", name=directory.get('name', id) if directory else id)

    def verify(self, id, updated_params):
        return ['system']

    def run(self, id, updated_params):
        directory = self.datastore.get_by_id('directories', id)
        old_name = None

        if directory['immutable']:
            raise TaskException(errno.EPERM, 'Directory {0} is immutable'.format(directory['name']))

        if 'name' in updated_params:
            old_name = directory['name']
            if self.datastore.exists('directories', ('name', '=', updated_params['name']), ('id', '!=', id)):
                raise TaskException(errno.EEXIST, 'Directory {0} already exists'.format(updated_params['name']))

        if 'parameters' in updated_params:
            for k, v in updated_params['parameters'].items():
                if k == 'password':
                    updated_params['parameters'][k] = unpassword(v)

        directory.update(updated_params)
        self.datastore.update('directories', id, directory)
        self.dispatcher.call_sync('dscached.management.configure_directory', id)
        self.dispatcher.dispatch_event('directory.changed', {
            'operation': 'update',
            'ids': [id]
        })

        if old_name:
            node = ConfigNode('directory', self.configstore)
            search_order = node['search_order'].value
            if old_name in search_order:
                search_order.remove(old_name)
                search_order.append(directory['name'])
                node['search_order'] = search_order

            self.dispatcher.call_sync('dscached.management.reload_config')


@accepts(str)
class DirectoryServiceDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting a directory"

    def describe(self, id):
        directory = self.datastore.get_by_id('directories', id)
        return TaskDescription("Deleting directory {name}", name=directory.get('name', id) if directory else id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        directory = self.datastore.get_by_id('directories', id)
        if not directory:
            raise TaskException(errno.ENOENT, 'Directory not found')

        name = directory['name']
        if directory['immutable']:
            raise TaskException(errno.EPERM, 'Directory {0} is immutable'.format(directory['name']))

        self.datastore.delete('directories', id)
        self.dispatcher.call_sync('dscached.management.configure_directory', id)
        self.dispatcher.dispatch_event('directory.changed', {
            'operation': 'delete',
            'ids': [id]
        })

        node = ConfigNode('directory', self.configstore)
        node['search_order'] = [i for i in node['search_order'].value if i != name]
        self.dispatcher.call_sync('dscached.management.reload_config')


def collect_debug(dispatcher):
    yield AttachRPC('directoryservice-config', 'directoryservice.get_config')
    yield AttachRPC('directory-query', 'directory.query')


def _init(dispatcher, plugin):
    plugin.register_schema_definition('DirectoryserviceConfig', {
        'type': 'object',
        'properties': {
            'search_order': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'cache_ttl': {'type': 'integer'},
            'cache_enumerations': {'type': 'boolean'},
            'cache_lookups': {'type': 'boolean'}
        }
    })

    plugin.register_schema_definition('DirectoryParams', {
        'discriminator': '%type',
        'oneOf': [
            {'$ref': '{0}DirectoryParams'.format(name)} for name in ('Winbind', 'Freeipa', 'Ldap', 'Nis')
        ]
    })

    plugin.register_schema_definition('Directory',  {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {
                'type': 'string',
                'minLength': 1
            },
            'type': {
                'type': 'string',
                'enum': ['file', 'local', 'winbind', 'freeipa', 'ldap', 'nis']
            },
            'enabled': {'type': 'boolean'},
            'enumerate': {'type': 'boolean'},
            'uid_range': {
                'type': ['array', 'null'],
                'items': [
                    {'type': 'integer'},
                    {'type': 'integer'}
                ]
            },
            'gid_range': {
                'type': ['array', 'null'],
                'items': [
                    {'type': 'integer'},
                    {'type': 'integer'}
                ]
            },
            'parameters': {'$ref': 'DirectoryParams'},
            'status': {'$ref': 'DirectoryStatus'}
        }
    })

    plugin.register_schema_definition('DirectoryStatus', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'state': {
                'type': 'string',
                'enum': ['DISABLED', 'JOINING', 'FAILURE', 'BOUND', 'EXITING']
            },
            'status_code': {'type': 'integer'},
            'status_message': {'type': ['string', 'null']}
        }
    })

    plugin.register_provider('directoryservice', DirectoryServiceProvider)
    plugin.register_provider('directory', DirectoryProvider)
    plugin.register_event_type('directory.changed')
    plugin.register_event_type('directoryservice.changed')
    plugin.register_task_handler('directory.create', DirectoryServiceCreateTask)
    plugin.register_task_handler('directory.update', DirectoryServiceUpdateTask)
    plugin.register_task_handler('directory.delete', DirectoryServiceDeleteTask)
    plugin.register_task_handler('directoryservice.update', DirectoryServicesConfigureTask)
    plugin.register_task_handler('directoryservice.flush_cache', DirectoryServiceFlushCacheTask)
    plugin.register_debug_hook(collect_debug)
