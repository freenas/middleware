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

import errno
import pwd
import datetime
import logging
import smbconf
from task import Task, Provider, TaskException, TaskDescription, VerifyException
from freenas.dispatcher.rpc import RpcException, description, accepts, private
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.utils import normalize


CONFIG_VERSION = 100000
logger = logging.getLogger(__name__)


@description("Provides info about configured SMB shares")
class SMBSharesProvider(Provider):
    @private
    def get_connected_clients(self, share_name=None):
        result = []
        for i in smbconf.get_active_users():
            try:
                user = self.dispatcher.threaded(pwd.getpwuid, i.uid).pw_name
            except KeyError:
                user = None

            result.append({
                'host': i.machine,
                'share': i.service_name,
                'user': user,
                'connected_at': datetime.datetime.utcfromtimestamp(i.start),
                'extra': {}
            })

        return result


@private
@description("Adds new SMB share")
@accepts(h.ref('Share'))
class CreateSMBShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating SMB share"

    def describe(self, share):
        return TaskDescription("Creating SMB share {name}", name=share.get('name', '') if share else '')

    def verify(self, share):
        if share['properties'].get('guest_only') and not share['properties'].get('guest_ok'):
            raise VerifyException(errno.EINVAL, 'guest_only works only with guest_ok enabled')

        return ['service:smb']

    def run(self, share):
        normalize(share['properties'], {
            'read_only': False,
            'guest_ok': False,
            'guest_only': False,
            'browseable': True,
            'recyclebin': False,
            'show_hidden_files': False,
            'previous_versions': True,
            'vfs_objects': [],
            'hosts_allow': [],
            'hosts_deny': [],
            'users_allow': [],
            'users_deny': [],
            'groups_allow': [],
            'groups_deny': [],
            'extra_parameters': {},
            'full_audit_prefix': '%u|%I|%m|%S',
            'full_audit_priority': 'notice',
            'full_audit_failure': 'connect',
            'full_audit_success': 'open mkdir unlink rmdir rename',
            'case_sensitive': 'AUTO',
            'allocation_roundup_size': 1048576,
            'ea_support': False,
            'store_dos_attributes': False,
            'map_archive': True,
            'map_hidden': False,
            'map_readonly': True,
            'map_system': False,
            'fruit_metadata': 'STREAM'

        })

        id = self.datastore.insert('shares', share)
        path = self.dispatcher.call_sync('share.translate_path', id)

        try:
            smb_conf = smbconf.SambaConfig('registry')
            smb_conf.transaction_start()
            try:
                smb_share = smbconf.SambaShare()
                convert_share(self.dispatcher, smb_share, path, share['enabled'], share['properties'])
                smb_conf.shares[share['name']] = smb_share
            except BaseException as err:
                smb_conf.transaction_cancel()
                raise TaskException(errno.EBUSY, 'Failed to update samba configuration: {0}', err)
            else:
                smb_conf.transaction_commit()

            reload_samba()
        except smbconf.SambaConfigException:
            raise TaskException(errno.EFAULT, 'Cannot access samba registry')

        self.dispatcher.dispatch_event('share.smb.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@private
@description("Updates existing SMB share")
@accepts(str, h.ref('Share'))
class UpdateSMBShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating SMB share"

    def describe(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        return TaskDescription("Updating SMB share {name}", name=share.get('name', id) if share else id)

    def verify(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        share.update(updated_fields)

        if share['properties'].get('guest_only') and not share['properties'].get('guest_ok'):
            raise VerifyException(errno.EINVAL, 'guest_only works only with guest_ok enabled')

        return ['service:smb']

    def run(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        oldname = share['name']
        newname = updated_fields.get('name', oldname)
        share.update(updated_fields)
        self.datastore.update('shares', id, share)
        path = self.dispatcher.call_sync('share.translate_path', share['id'])

        try:
            smb_conf = smbconf.SambaConfig('registry')
            smb_conf.transaction_start()
            try:
                if oldname != newname:
                    del smb_conf.shares[oldname]
                    smb_share = smbconf.SambaShare()
                    smb_conf.shares[newname] = smb_share

                smb_share = smb_conf.shares[newname]
                convert_share(self.dispatcher, smb_share, path, share['enabled'], share['properties'])
                smb_share.save()
            except BaseException as err:
                smb_conf.transaction_cancel()
                raise TaskException(errno.EBUSY, f'Failed to update samba configuration: {err}')
            else:
                smb_conf.transaction_commit()

            reload_samba()

            if not share['enabled']:
                drop_share_connections(share['name'])
        except smbconf.SambaConfigException:
            raise TaskException(errno.EFAULT, 'Cannot access samba registry')

        self.dispatcher.dispatch_event('share.smb.changed', {
            'operation': 'update',
            'ids': [id]
        })


@private
@description("Removes SMB share")
@accepts(str)
class DeleteSMBShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting SMB share"

    def describe(self, id):
        share = self.datastore.get_by_id('shares', id)
        return TaskDescription("Deleting SMB share {name}", name=share.get('name', id) if share else id)

    def verify(self, id):
        return ['service:smb']

    def run(self, id):
        share = self.datastore.get_by_id('shares', id)
        self.datastore.delete('shares', id)

        try:
            smb_conf = smbconf.SambaConfig('registry')
            smb_conf.transaction_start()
            try:
                del smb_conf.shares[share['name']]
            except BaseException as err:
                smb_conf.transaction_cancel()
                raise TaskException(errno.EBUSY, 'Failed to update samba configuration: {0}', err)
            else:
                smb_conf.transaction_commit()

            reload_samba()
            drop_share_connections(share['name'])
        except smbconf.SambaConfigException:
            raise TaskException(errno.EFAULT, 'Cannot access samba registry')

        self.dispatcher.dispatch_event('share.smb.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@private
@description("Imports existing SMB share")
@accepts(h.ref('Share'))
class ImportSMBShareTask(CreateSMBShareTask):
    @classmethod
    def early_describe(cls):
        return "Importing SMB share"

    def describe(self, share):
        return TaskDescription("Importing SMB share {name}", name=share.get('name', '') if share else '')

    def verify(self, share):
        return super(ImportSMBShareTask, self).verify(share)

    def run(self, share):
        return super(ImportSMBShareTask, self).run(share)


@description('Terminates SMB connection')
class TerminateSMBConnectionTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Terminating SMB connection'

    def describe(self, address):
        return TaskDescription('Terminating SMB connection with {name}', name=address)

    def verify(self, address):
        return ['system']

    def run(self, address):
        try:
            rpc = smbconf.SambaMessagingContext()
            rpc.kill_user_connection(address)
        except OSError as err:
            raise TaskException(err.errno, 'Cannot terminate connections: {0}'.format(str(err)))


def yesno(val):
    return 'yes' if val else 'no'


def reload_samba():
    try:
        rpc = smbconf.SambaMessagingContext()
        rpc.reload_config()
    except OSError as err:
        logger.info('Cannot reload samba config: {0}'.format(str(err)))


def drop_share_connections(share):
    try:
        rpc = smbconf.SambaMessagingContext()
        rpc.kill_share_connections(share)
    except OSError as err:
        logger.info('Cannot reload samba config: {0}'.format(str(err)))


def convert_share(dispatcher, ret, path, enabled, share):
    vfs_objects = ['zfsacl', 'zfs_space'] + share.get('vfs_objects', [])
    ret.clear()
    ret['path'] = path
    ret['available'] = yesno(enabled)
    ret['guest ok'] = yesno(share['guest_ok'])
    ret['guest only'] = yesno(share['guest_only'])
    ret['read only'] = yesno(share['read_only'])
    ret['browseable'] = yesno(share['browseable'])
    ret['hide dot files'] = yesno(not share['show_hidden_files'])
    ret['printable'] = 'no'
    ret['nfs4:mode'] = 'special'
    ret['nfs4:acedup'] = 'merge'
    ret['nfs4:chown'] = 'true'
    ret['zfsacl:acesort'] = 'dontcare'
    ret['case sensitive'] = share['case_sensitive'].lower()
    ret['allocation roundup size'] = str(share['allocation_roundup_size'])
    ret['ea support'] = yesno(share['ea_support'])
    ret['store dos attributes'] = yesno(share['store_dos_attributes'])
    ret['map archive'] = yesno(share['map_archive'])
    ret['map hidden'] = yesno(share['map_hidden'])
    ret['map readonly'] = yesno(share['map_readonly'])
    ret['map system'] = yesno(share['map_system'])

    if 'fruit' in vfs_objects:
        ret['fruit:metadata'] = share['fruit_metadata'].lower()

    if share.get('hosts_allow'):
        ret['hosts allow'] = ','.join(share['hosts_allow'])

    if share.get('hosts_deny'):
        ret['hosts deny'] = ','.join(share['hosts_deny'])

    if share.get('users_allow') or share.get('groups_allow'):
        ret['valid users'] = ' '.join(
            [f'"{i}"' for i in share.get('users_allow', [])] +
            [f'"@{i}"' for i in share.get('groups_allow', [])]
        )

    if share.get('users_deny') or share.get('groups_deny'):
        ret['invalid users'] = ' '.join(
            [f'"{i}"' for i in share.get('users_deny', [])] +
            [f'"@{i}"' for i in share.get('groups_deny', [])]
        )

    if share.get('recyclebin'):
        ret['recycle:repository'] = '.recycle/%U'
        ret['recycle:keeptree'] = 'yes'
        ret['recycle:versions'] = 'yes'
        ret['recycle:touch'] = 'yes'
        ret['recycle:directory_mode'] = '0777'
        ret['recycle:subdir_mode'] = '0700'
        vfs_objects.append('recycle')

    if 'full_audit' in vfs_objects:
        ret['full_audit:prefix'] = share['full_audit_prefix']
        ret['full_audit:priority'] = share['full_audit_priority']
        ret['full_audit:failure'] = share['full_audit_failure']
        ret['full_audit:success'] = share['full_audit_success']

    if share.get('previous_versions'):
        try:
            volume, dataset, _ = dispatcher.call_sync('volume.decode_path', path)
            vfs_objects.insert(0, 'shadow_copy_zfs')
            ret['shadow:dataset'] = dataset
            ret['shadow:sort'] = 'desc'
        except RpcException as err:
            logger.warning('Failed to determine dataset for path {0}: {1}'.format(path, str(err)))

    ret['vfs objects'] = ' '.join(vfs_objects + ['aio_pthread'])

    for k, v in share['extra_parameters'].items():
        ret[k] = str(v)


def _depends():
    return ['SharingPlugin', 'SMBPlugin']


def _metadata():
    return {
        'type': 'sharing',
        'subtype': 'FILE',
        'perm_type': 'ACL',
        'method': 'smb',
        'version': CONFIG_VERSION
    }


def _init(dispatcher, plugin):
    plugin.register_schema_definition('ShareSmb', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['ShareSmb']},
            'comment': {'type': 'string'},
            'read_only': {'type': 'boolean'},
            'guest_ok': {'type': 'boolean'},
            'guest_only': {'type': 'boolean'},
            'browseable': {'type': 'boolean'},
            'recyclebin': {'type': 'boolean'},
            'show_hidden_files': {'type': 'boolean'},
            'previous_versions': {'type': 'boolean'},
            'home_share': {'type': 'boolean'},
            'full_audit_prefix': {'type': 'string'},
            'full_audit_priority': {'type': 'string'},
            'full_audit_failure': {'type': 'string'},
            'full_audit_success': {'type': 'string'},
            'case_sensitive': {'type': 'string', 'enum': ['AUTO', 'YES', 'NO']},
            'allocation_roundup_size': {'type': 'integer'},
            'ea_support': {'type': 'boolean'},
            'store_dos_attributes': {'type': 'boolean'},
            'map_archive': {'type': 'boolean'},
            'map_hidden': {'type': 'boolean'},
            'map_readonly': {'type': 'boolean'},
            'map_system': {'type': 'boolean'},
            'fruit_metadata': {'type': 'string', 'enum': ['STREAM', 'NETATALK']},
            'vfs_objects': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'hosts_allow': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'hosts_deny': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'users_allow': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'groups_allow': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'users_deny': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'groups_deny': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'extra_parameters': {
                'type': 'object',
                'additionalProperties': {'type': 'string'}
            }
        }
    })

    plugin.register_task_handler("share.smb.create", CreateSMBShareTask)
    plugin.register_task_handler("share.smb.update", UpdateSMBShareTask)
    plugin.register_task_handler("share.smb.delete", DeleteSMBShareTask)
    plugin.register_task_handler("share.smb.import", ImportSMBShareTask)
    plugin.register_task_handler("share.smb.terminate_connection", TerminateSMBConnectionTask)
    plugin.register_provider("share.smb", SMBSharesProvider)
    plugin.register_event_type('share.smb.changed')

    # Sync samba registry with our database
    smb_conf = smbconf.SambaConfig('registry')
    smb_conf.transaction_start()
    try:
        smb_conf.shares.clear()

        for s in dispatcher.datastore.query_stream('shares', ('type', '=', 'smb')):
            smb_share = smbconf.SambaShare()
            path = dispatcher.call_sync('share.translate_path', s['id'])
            convert_share(dispatcher, smb_share, path, s['enabled'], s.get('properties', {}))
            smb_conf.shares[s['name']] = smb_share
    except BaseException as err:
        logger.error('Failed to update samba registry: {0}'.format(err), exc_info=True)
        smb_conf.transaction_cancel()
    else:
        smb_conf.transaction_commit()
