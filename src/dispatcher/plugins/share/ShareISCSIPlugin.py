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
import errno
import uuid
import hashlib
import ctl
from debug import AttachFile
from utils import is_port_open
from task import Task, Provider, VerifyException, TaskDescription, TaskException
from freenas.dispatcher.rpc import RpcException, description, accepts, returns, private, generator
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.utils import normalize, query as q


IQN_NAME_REGEX = '^[a-zA-Z0-9-:\.]+$'


def validate_portal_port(listen):
    if listen:
        for host in listen:
            if not not is_port_open(host['port']):
                raise TaskException(
                    errno.EFAULT,
                    'Provided port {} is already in use'.format(host['port'])
                )


def check_auth_group_mode(datastore, discovery_auth_group):
    if discovery_auth_group:
        if discovery_auth_group == 'no-authentication':
            return
        if not datastore.exists('iscsi.auth', ('id', '=', discovery_auth_group)):
            raise TaskException(
                errno.ENOENT,
                'Auth group {0} does not exist'.format(discovery_auth_group)
            )
        else:
            auth_group = datastore.get_by_id('iscsi.auth', discovery_auth_group)
            if auth_group['type'] in ('NONE', 'DENY'):
                raise TaskException(errno.EPERM, 'Auth group cannot be in NONE or DENY mode')


@description("Provides info about configured iSCSI shares")
class ISCSISharesProvider(Provider):
    @private
    @accepts(str)
    def get_connected_clients(self, share_name=None):
        handle = ctl.CTL()
        result = []
        base_name = self.configstore.get('service.iscsi.base_name')

        for conn in handle.iscsi_connections:
            # Add entry for every lun mapped in this target
            target = self.datastore.get_by_id('iscsi.targets', conn.target)
            if not target:
                target = self.datastore.get_by_id('iscsi.targets', f'{base_name}:{conn.target}')

            if not target:
                continue

            for lun in target['extents']:
                result.append({
                    'host': conn.initiator_address,
                    'share': lun['name'],
                    'user': conn.initiator,
                    'connected_at': None,
                    'extra': {}
                })

        return result

    @returns(str)
    def generate_serial(self):
        nic = self.dispatcher.call_sync('network.interface.query', [('type', '=', 'ETHER')], {'single': True})
        laddr = q.get(nic, 'status.link_address').replace(':', '')
        idx = 0

        while True:
            serial = '{0}{1:02}'.format(laddr, idx)
            if self.datastore.exists('shares', ('properties.serial', '=', serial)):
                idx += 1
                continue

            if self.datastore.exists('simulator.disks', ('serial', '=', serial)):
                idx += 1
                continue

            return serial

        raise RpcException(errno.EBUSY, 'No free serial numbers found')

    @private
    @returns(str)
    def generate_naa(self):
        return '0x6589cfc000000{0}'.format(hashlib.sha256(uuid.uuid4().bytes).hexdigest()[0:19])


@description('Provides information about iSCSI targets')
class ISCSITargetsProvider(Provider):
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('iscsi.targets', *(filter or []), **(params or {}))


@description('Provides information about iSCSI auth groups')
class ISCSIAuthProvider(Provider):
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('iscsi.auth', *(filter or []), **(params or {}))


@description('Provides information about iSCSI portals')
class ISCSIPortalProvider(Provider):
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('iscsi.portals', *(filter or []), **(params or {}))


@private
@accepts(h.ref('ShareIscsi'))
@description("Adds new iSCSI share")
class CreateISCSIShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating iSCSI share"

    def describe(self, share):
        return TaskDescription("Creating iSCSI share {name}", name=share.get('name', '') if share else '')

    def verify(self, share):
        if share['target_type'] == 'FILE':
            # File extent
            if not os.path.exists(share['target_path']):
                raise VerifyException(errno.ENOENT, "Extent file does not exist")
        elif share['target_type'] == 'ZVOL':
            if not os.path.exists(os.path.join('/dev/zvol', share['target_path'])):
                raise VerifyException(errno.ENOENT, "Extent ZVol does not exist")
        else:
            raise VerifyException(errno.EINVAL, 'Unsupported target type {0}'.format(share['target_type']))

        return ['system']

    def run(self, share):
        props = share['properties']
        normalize(props, {
            'serial': self.dispatcher.call_sync('share.iscsi.generate_serial'),
            'block_size': 512,
            'physical_block_size': True,
            'tpc': False,
            'vendor_id': None,
            'product_id': None,
            'device_id': None,
            'rpm': 'SSD',
            'read_only': False,
            'xen_compat': False,
            'naa': self.dispatcher.call_sync('share.iscsi.generate_naa')
        })

        id = self.datastore.insert('shares', share)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')

        self.dispatcher.dispatch_event('share.iscsi.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@private
@accepts(str, h.ref('ShareIscsi'))
@description("Updates existing iSCSI share")
class UpdateISCSIShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating iSCSI share"

    def describe(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        return TaskDescription("Updating iSCSI share {name}", name=share.get('name', id) if share else id)

    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        share.update(updated_fields)
        self.datastore.update('shares', id, share)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')

        self.dispatcher.dispatch_event('share.iscsi.changed', {
            'operation': 'update',
            'ids': [id]
        })


@private
@accepts(str)
@description("Removes iSCSI share")
class DeleteiSCSIShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting iSCSI share"

    def describe(self, id):
        share = self.datastore.get_by_id('shares', id)
        return TaskDescription("Deleting iSCSI share {name}", name=share.get('name', id) if share else id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        share = self.datastore.get_by_id('shares', id)

        # Check if share is mapped anywhere
        subtasks = []
        for i in self.datastore.query_stream('iscsi.targets'):
            if share['name'] in [m['name'] for m in i['extents']]:
                i['extents'] = list(filter(lambda e: e['name'] != share['name'], i['extents']))
                subtasks.append(self.run_subtask('share.iscsi.target.update', i['id'], i))

        self.join_subtasks(*subtasks)

        self.datastore.delete('shares', id)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')
        self.dispatcher.dispatch_event('share.iscsi.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@private
@accepts(h.ref('ShareIscsi'))
@description("Imports existing iSCSI share")
class ImportiSCSIShareTask(CreateISCSIShareTask):
    @classmethod
    def early_describe(cls):
        return "Importing iSCSI share"

    def describe(self, share):
        return TaskDescription("Importing iSCSI share {name}", name=share.get('name', '') if share else '')

    def verify(self, share):
        return super(ImportiSCSIShareTask, self).verify(share)

    def run(self, share):
        return super(ImportiSCSIShareTask, self).run(share)


@accepts(h.all_of(
    h.ref('ShareIscsiTarget'),
    h.required('id')
))
@description('Creates iSCSI share target')
class CreateISCSITargetTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating iSCSI share target'

    def describe(self, target):
        return TaskDescription('Creating iSCSI share target {name}', name=target.get('id', '') if target else '')

    def verify(self, target):
        return ['system']

    def run(self, target):
        for i in target.get('extents', []):
            if not self.datastore.exists('shares', ('type', '=', 'iscsi'), ('name', '=', i['name'])):
                raise TaskException(errno.ENOENT, "Share {0} not found".format(i['name']))

        normalize(target, {
            'description': None,
            'auth_group': 'no-authentication',
            'portal_group': 'default',
            'extents': []
        })

        id = self.datastore.insert('iscsi.targets', target)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')
        self.dispatcher.dispatch_event('iscsi.target.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@accepts(str, h.ref('ShareIscsiTarget'))
@description('Updates iSCSI share target')
class UpdateISCSITargetTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating iSCSI share target'

    def describe(self, id, updated_params):
        return TaskDescription('Updating iSCSI share target {name}', name=id)

    def verify(self, id, updated_params):
        return ['system']

    def run(self, id, updated_params):
        if not self.datastore.exists('iscsi.targets', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Target {0} does not exist'.format(id))

        if 'extents' in updated_params:
            seen_numbers = []
            for i in updated_params['extents']:
                if not self.datastore.exists('shares', ('type', '=', 'iscsi'), ('name', '=', i['name'])):
                    raise TaskException(errno.ENOENT, "Share {0} not found".format(i['name']))

                if i['number'] in seen_numbers:
                    raise TaskException(errno.EEXIST, "LUN number {0} used twice".format(i['number']))

                seen_numbers.append(i['number'])

        target = self.datastore.get_by_id('iscsi.targets', id)
        target.update(updated_params)
        self.datastore.update('iscsi.targets', id, target)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')
        self.dispatcher.dispatch_event('iscsi.target.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str)
@description('Deletes iSCSI share target')
class DeleteISCSITargetTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting iSCSI share target'

    def describe(self, id):
        return TaskDescription('Deleting iSCSI share target {name}', name=id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('iscsi.targets', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Target {0} does not exist'.format(id))

        self.datastore.delete('iscsi.targets', id)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')
        self.dispatcher.dispatch_event('iscsi.target.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@accepts(
    h.all_of(
        h.ref('ShareIscsiAuth'),
        h.required('type')
    )
)
@description('Creates iSCSI auth group')
class CreateISCSIAuthGroupTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating iSCSI auth group'

    def describe(self, auth_group):
        return TaskDescription('Creating iSCSI auth group {name}', name=auth_group.get('id', ''))

    def verify(self, auth_group):
        return ['system']

    def run(self, auth_group):
        normalize(auth_group, {
            'id': self.datastore.collection_get_next_pkey('iscsi.auth', 'ag'),
            'users': None,
            'initiators': None,
            'networks': None
        })

        id = self.datastore.insert('iscsi.auth', auth_group)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')
        self.dispatcher.dispatch_event('iscsi.auth.changed', {
            'operation': 'create',
            'ids': [id]
        })
        return id


@accepts(str, h.ref('ShareIscsiAuth'))
@description('Updates iSCSI auth group')
class UpdateISCSIAuthGroupTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating iSCSI auth group'

    def describe(self, id, updated_params):
        return TaskDescription('Updating iSCSI auth group {name}', name=id)

    def verify(self, id, updated_params):
        return ['system']

    def run(self, id, updated_params):
        if not self.datastore.exists('iscsi.auth', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Auth group {0} does not exist'.format(id))

        ag = self.datastore.get_by_id('iscsi.auth', id)
        ag.update(updated_params)
        self.datastore.update('iscsi.auth', id, ag)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')
        self.dispatcher.dispatch_event('iscsi.auth.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str)
@description('Deletes iSCSI auth group')
class DeleteISCSIAuthGroupTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting iSCSI auth group'

    def describe(self, id):
        return TaskDescription('Deleting iSCSI auth group {name}', name=id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('iscsi.auth', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Auth group {0} does not exist'.format(id))

        self.datastore.delete('iscsi.auth', id)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')
        self.dispatcher.dispatch_event('iscsi.auth.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@accepts(h.ref('ShareIscsiPortal'))
@description('Creates iSCSI portal')
class CreateISCSIPortalTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating iSCSI portal'

    def describe(self, portal):
        return TaskDescription('Creating iSCSI portal {name}', name=portal.get('id', ''))

    def verify(self, portal):
        return ['system']

    def run(self, portal):
        validate_portal_port(portal.get('listen'))
        check_auth_group_mode(self.datastore, portal.get('discovery_auth_group'))

        normalize(portal, {
            'id': self.datastore.collection_get_next_pkey('iscsi.portals', 'pg'),
            'discovery_auth_group': None,
            'discovery_auth_method': 'NONE',
            'portals': []
        })

        id = self.datastore.insert('iscsi.portals', portal)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')
        self.dispatcher.dispatch_event('iscsi.portal.changed', {
            'operation': 'create',
            'ids': [id]
        })
        return id


@accepts(str, h.ref('ShareIscsiPortal'))
@description('Updates iSCSI portal')
class UpdateISCSIPortalTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating iSCSI portal'

    def describe(self, id, updated_params):
        return TaskDescription('Updating iSCSI portal {name}', name=id)

    def verify(self, id, updated_params):
        return ['system']

    def run(self, id, updated_params):
        validate_portal_port(updated_params.get('listen'))
        check_auth_group_mode(self.datastore, updated_params.get('discovery_auth_group'))

        if not self.datastore.exists('iscsi.portals', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Portal {0} does not exist'.format(id))

        ag = self.datastore.get_by_id('iscsi.portals', id)
        ag.update(updated_params)
        self.datastore.update('iscsi.portals', id, ag)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')
        self.dispatcher.dispatch_event('iscsi.portal.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str)
@description('Deletes iSCSI portal')
class DeleteISCSIPortalTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting iSCSI portal'

    def describe(self, id):
        return TaskDescription('Deleting iSCSI portal {name}', name=id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('iscsi.portals', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Portal {0} does not exist'.format(id))

        self.datastore.delete('iscsi.portals', id)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.call_sync('service.reload', 'ctl')
        self.dispatcher.dispatch_event('iscsi.portal.changed', {
            'operation': 'delete',
            'ids': [id]
        })


def convert_share_target(target):
    if target[0] == '/':
        return target

    return os.path.join('/dev/zvol', target)


def collect_debug(dispatcher):
    yield AttachFile('ctl.conf', '/etc/ctl.conf.shadow')


def _metadata():
    return {
        'type': 'sharing',
        'subtype': 'BLOCK',
        'method': 'iscsi',
    }


def _depends():
    return ['SharingPlugin']


def _init(dispatcher, plugin):
    plugin.register_schema_definition('ShareIscsi', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['ShareIscsi']},
            'serial': {'type': 'string'},
            'ctl_lun': {'type': 'integer'},
            'naa': {'type': 'string'},
            'size': {'type': ['integer', 'null']},
            'block_size': {'$ref': 'ShareIscsiBlocksize'},
            'physical_block_size': {'type': 'boolean'},
            'available_space_threshold': {'type': ['integer', 'null']},
            'read_only': {'type': 'boolean'},
            'xen_compat': {'type': 'boolean'},
            'tpc': {'type': 'boolean'},
            'vendor_id': {'type': ['string', 'null']},
            'product_id': {'type': ['string', 'null']},
            'device_id': {'type': ['string', 'null']},
            'rpm': {'$ref': 'ShareIscsiRpm'}
        }
    })

    plugin.register_schema_definition('ShareIscsiBlocksize', {
        'type': 'integer',
        'enum': [512, 1024, 2048, 4096]
    })

    plugin.register_schema_definition('ShareIscsiRpm', {
        'type': 'string',
        'enum': ['UNKNOWN', 'SSD', '5400', '7200', '10000', '15000']
    })

    plugin.register_schema_definition('ShareIscsiTarget', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {
                'type': 'string',
                'pattern': IQN_NAME_REGEX
            },
            'description': {'type': 'string'},
            'auth_group': {'type': 'string'},
            'portal_group': {'type': 'string'},
            'extents': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'name': {'type': 'string'},
                        'number': {'type': 'integer'}
                    },
                    'required': ['name', 'number']
                },
            }
        }
    })

    plugin.register_schema_definition('ShareIscsiPortal', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'tag': {'type': 'integer'},
            'description': {'type': 'string'},
            'discovery_auth_group': {'type': ['string', 'null']},
            'listen': {'$ref': 'ShareIscsiPortalListen'}
        }
    })

    plugin.register_schema_definition('ShareIscsiPortalListen', {
        'type': 'array',
        'items': {
            'type': 'object',
            'additionalProperties': False,
            'properties': {
                'address': {'type': 'string', 'format': 'ip-address'},
                'port': {
                    'type': 'integer',
                    'minimum': 1024,
                    'maximum': 65535
                }
            }
        }
    })

    plugin.register_schema_definition('ShareIscsiAuth', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'description': {'type': 'string'},
            'type': {'$ref': 'ShareIscsiAuthType'},
            'users': {
                'type': ['array', 'null'],
                'items': {'$ref': 'ShareIscsiUser'}
            },
            'initiators': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'networks': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
        }
    })

    plugin.register_schema_definition('ShareIscsiAuthType', {
        'type': 'string',
        'enum': ['NONE', 'DENY', 'CHAP', 'CHAP_MUTUAL']
    })

    plugin.register_schema_definition('ShareIscsiUser', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'name': {'type': 'string'},
            'secret': {'type': 'string', 'minLength': 12, 'maxLength': 16},
            'peer_name': {'type': ['string', 'null']},
            'peer_secret': {'type': ['string', 'null'], 'minLength': 12, 'maxLength': 16}
        }
    })

    plugin.register_task_handler("share.iscsi.create", CreateISCSIShareTask)
    plugin.register_task_handler("share.iscsi.update", UpdateISCSIShareTask)
    plugin.register_task_handler("share.iscsi.delete", DeleteiSCSIShareTask)
    plugin.register_task_handler("share.iscsi.import", ImportiSCSIShareTask)
    plugin.register_task_handler("share.iscsi.target.create", CreateISCSITargetTask)
    plugin.register_task_handler("share.iscsi.target.update", UpdateISCSITargetTask)
    plugin.register_task_handler("share.iscsi.target.delete", DeleteISCSITargetTask)
    plugin.register_task_handler("share.iscsi.auth.create", CreateISCSIAuthGroupTask)
    plugin.register_task_handler("share.iscsi.auth.update", UpdateISCSIAuthGroupTask)
    plugin.register_task_handler("share.iscsi.auth.delete", DeleteISCSIAuthGroupTask)
    plugin.register_task_handler("share.iscsi.portal.create", CreateISCSIPortalTask)
    plugin.register_task_handler("share.iscsi.portal.update", UpdateISCSIPortalTask)
    plugin.register_task_handler("share.iscsi.portal.delete", DeleteISCSIPortalTask)

    plugin.register_provider("share.iscsi", ISCSISharesProvider)
    plugin.register_provider("share.iscsi.target", ISCSITargetsProvider)
    plugin.register_provider("share.iscsi.auth", ISCSIAuthProvider)
    plugin.register_provider("share.iscsi.portal", ISCSIPortalProvider)
    plugin.register_event_type('share.iscsi.changed')
    plugin.register_debug_hook(collect_debug)
