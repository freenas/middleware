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

import os
import errno
import logging
import re
import smbconf
import enum
import contextlib
from datastore.config import ConfigNode
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns, private
from lib.system import system, SubprocessException
from lib.freebsd import get_sysctl
from task import Task, Provider, TaskException, TaskDescription
from debug import AttachFile, AttachCommandOutput
from freenas.utils.permissions import get_unix_permissions, get_integer, perm_to_oct_string

logger = logging.getLogger('SMBPlugin')


class LogLevel(enum.IntEnum):
    NONE = 0
    MINIMUM = 1
    NORMAL = 2
    FULL = 3
    DEBUG = 10


def validate_netbios_name(netbiosname):
    regex = re.compile(r"^[a-zA-Z0-9\.\-_!@#\$%^&\(\)'\{\}~]{1,15}$")
    return regex.match(netbiosname)


@description('Provides info about SMB service configuration')
class SMBProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('ServiceSmb'))
    def get_config(self):
        config = ConfigNode('service.smb', self.configstore).__getstate__()
        if 'filemask' in config:
            if config['filemask'] is not None:
                config['filemask'] = get_unix_permissions(config['filemask'])
        if 'dirmask' in config:
            if config['dirmask'] is not None:
                config['dirmask'] = get_unix_permissions(config['dirmask'])
        return config

    @returns(bool)
    def ad_enabled(self):
        return self.datastore.exists('directories', ('type', '=', 'winbind'), ('enabled', '=', True))


@private
@description('Configure SMB service')
@accepts(h.ref('ServiceSmb'))
class SMBConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring SMB service'

    def describe(self, smb):
        return TaskDescription('Configuring SMB service')

    def verify(self, smb):
        return ['system']

    def run(self, smb):
        node = ConfigNode('service.smb', self.configstore).__getstate__()
        netbiosname = smb.get('netbiosname')
        if netbiosname is not None:
            for n in netbiosname:
                if not validate_netbios_name(n):
                    raise TaskException(errno.EINVAL, 'Invalid name {0}'.format(n))
        else:
            netbiosname = node['netbiosname']

        workgroup = smb.get('workgroup')
        if workgroup is not None:
            if not validate_netbios_name(workgroup):
                raise TaskException(errno.EINVAL, 'Invalid name')
        else:
            workgroup = node['workgroup']

        if workgroup.lower() in [i.lower() for i in netbiosname]:
            raise TaskException(errno.EINVAL, 'NetBIOS and Workgroup must be unique')

        if smb.get('guest_user'):
            if not self.dispatcher.call_sync('user.query', [('username', '=', smb['guest_user'])], {'single': True}):
                raise TaskException(errno.EINVAL, 'User: {0} does not exist'.format(smb['guest_user']))

        try:
            action = 'NONE'
            node = ConfigNode('service.smb', self.configstore)
            if smb.get('filemask'):
                smb['filemask'] = get_integer(smb['filemask'])

            if smb.get('dirmask'):
                smb['dirmask'] = get_integer(smb['dirmask'])

            node.update(smb)
            configure_params(node.__getstate__(), self.dispatcher.call_sync('service.smb.ad_enabled'))

            try:
                rpc = smbconf.SambaMessagingContext()
                rpc.reload_config()
            except OSError:
                action = 'RESTART'

            # XXX: Is restart to change netbios name/workgroup *really* needed?
            if 'netbiosname' in smb or 'workgroup' in smb:
                action = 'RESTART'

            self.dispatcher.dispatch_event('service.smb.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure SMB: {0}'.format(str(e))
            )

        return action


def yesno(val):
    return 'yes' if val else 'no'


def configure_params(smb, ad=False):
    conf = smbconf.SambaConfig('registry')
    conf.transaction_start()
    try:
        conf['netbios name'] = smb['netbiosname'][0]
        conf['netbios aliases'] = ' '.join(smb['netbiosname'][1:])

        if smb['bind_addresses']:
            conf['interfaces'] = ' '.join(['127.0.0.1'] + smb['bind_addresses'])

        conf['server string'] = smb['description']
        conf['server max protocol'] = smb['max_protocol']
        conf['server min protocol'] = smb['min_protocol']
        conf['encrypt passwords'] = 'yes'
        conf['dns proxy'] = 'no'
        conf['strict locking'] = 'no'
        conf['oplocks'] = 'yes'
        conf['deadtime'] = '15'
        conf['max log size'] = '51200'
        conf['max open files'] = str(int(get_sysctl('kern.maxfilesperproc')) - 25)
        conf['logging'] = 'logd@10'

        if 'filemask' in smb:
            if smb['filemask'] is not None:
                conf['create mode'] = perm_to_oct_string(get_unix_permissions(smb['filemask'])).zfill(4)

        if 'dirmask' in smb:
            if smb['dirmask'] is not None:
                conf['directory mode'] = perm_to_oct_string(get_unix_permissions(smb['dirmask'])).zfill(4)

        conf['load printers'] = 'no'
        conf['printing'] = 'bsd'
        conf['printcap name'] = '/dev/null'
        conf['disable spoolss'] = 'yes'
        conf['getwd cache'] = 'yes'
        conf['guest account'] = smb['guest_user']
        conf['map to guest'] = 'Bad User'
        conf['obey pam restrictions'] = yesno(smb['obey_pam_restrictions'])
        conf['directory name cache size'] = '0'
        conf['kernel change notify'] = 'no'
        conf['panic action'] = '/usr/local/libexec/samba/samba-backtrace'
        conf['nsupdate command'] = '/usr/local/bin/samba-nsupdate -g'
        conf['ea support'] = 'yes'
        conf['store dos attributes'] = 'yes'
        conf['lm announce'] = 'yes'
        conf['hostname lookups'] = yesno(smb['hostlookup'])
        conf['unix extensions'] = yesno(smb['unixext'])
        conf['time server'] = yesno(smb['time_server'])
        conf['acl allow execute always'] = yesno(smb['execute_always'])
        conf['dos filemode'] = 'yes'
        conf['multicast dns register'] = yesno(smb['zeroconf'])
        conf['passdb backend'] = 'freenas'
        conf['log level'] = str(getattr(LogLevel, smb['log_level']).value)
        conf['username map'] = '/usr/local/etc/smbusers'
        conf['idmap config *: range'] = '90000001-100000000'
        conf['idmap config *: backend'] = 'tdb'
        conf['ntlm auth'] = 'yes'

        if not ad:
            conf['local master'] = yesno(smb['local_master'])
            conf['server role'] = 'auto'
            conf['workgroup'] = smb['workgroup']
    except BaseException as err:
        logger.error('Failed to update samba registry: {0}'.format(err), exc_info=True)
        conf.transaction_cancel()
    else:
        conf.transaction_commit()


def collect_debug(dispatcher):
    yield AttachFile('smb4.conf', '/usr/local/etc/smb4.conf')
    yield AttachCommandOutput('net-conf-list', ['/usr/local/bin/net', 'conf', 'list'])
    yield AttachCommandOutput('net-getlocalsid', ['/usr/local/bin/net', 'getlocalsid'])
    yield AttachCommandOutput('net-getdomainsid', ['/usr/local/bin/net', 'getdomainsid'])
    yield AttachCommandOutput('net-groupmap-list', ['/usr/local/bin/net', 'groupmap', 'list'])
    yield AttachCommandOutput('net-status-sessions', ['/usr/local/bin/net', 'status', 'sessions'])
    yield AttachCommandOutput('net-status-shares', ['/usr/local/bin/net', 'status', 'shares'])
    yield AttachCommandOutput('wbinfo-users', ['/usr/local/bin/wbinfo', '-u'])
    yield AttachCommandOutput('wbinfo-groups', ['/usr/local/bin/wbinfo', '-g'])


def _depends():
    return ['ServiceManagePlugin', 'SystemDatasetPlugin']


def _init(dispatcher, plugin):

    def set_smb_sid():
        smb = dispatcher.call_sync('service.smb.get_config')
        if not smb['sid']:
            try:
                sid = system('/usr/local/bin/net', 'getlocalsid')[0]
                if ':' in sid:
                    sid = sid.split(':', 1)[1].strip(' ').strip('\n')
                    if sid:
                        dispatcher.configstore.set('service.smb.sid', sid)
                        smb['sid'] = sid
            except SubprocessException:
                logger.error('Failed to get local sid', exc_info=True)
        try:
            if smb['sid']:
                system('/usr/local/bin/net', 'setlocalsid', smb['sid'])
        except SubprocessException as err:
            logger.error('Failed to set local sid: {0}'.format(err.output))

    # Register schemas
    PROTOCOLS = [
        'CORE',
        'COREPLUS',
        'LANMAN1',
        'LANMAN2',
        'NT1',
        'SMB2',
        'SMB2_02',
        'SMB2_10',
        'SMB2_22',
        'SMB2_24',
        'SMB3',
        'SMB3_00',
    ]

    plugin.register_schema_definition('ServiceSmb', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceSmb']},
            'enable': {'type': 'boolean'},
            'netbiosname': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'workgroup': {'type': 'string'},
            'description': {'type': 'string'},
            'dos_charset': {'$ref': 'ServiceSmbDoscharset'},
            'unix_charset': {'$ref': 'ServiceSmbUnixcharset'},
            'log_level': {'$ref': 'ServiceSmbLoglevel'},
            'local_master': {'type': 'boolean'},
            'domain_logons': {'type': 'boolean'},
            'time_server': {'type': 'boolean'},
            'guest_user': {'type': 'string'},
            'filemask': {
                'oneOf': [
                    {'$ref': 'UnixPermissions'},
                    {'type': 'null'}
                ]
            },
            'dirmask': {
                'oneOf': [
                    {'$ref': 'UnixPermissions'},
                    {'type': 'null'}
                ]
            },
            'unixext': {'type': 'boolean'},
            'zeroconf': {'type': 'boolean'},
            'hostlookup': {'type': 'boolean'},
            'min_protocol': {'$ref': 'ServiceSmbMinprotocol'},
            'max_protocol': {'$ref': 'ServiceSmbMaxprotocol'},
            'execute_always': {'type': 'boolean'},
            'obey_pam_restrictions': {'type': 'boolean'},
            'bind_addresses': {
                'type': ['array', 'null'],
                'items': {'type': 'string'},
            },
            'auxiliary': {'type': ['string', 'null']},
            'sid': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('ServiceSmbDoscharset', {
        'type': 'string',
        'enum': [
            'CP437', 'CP850', 'CP852', 'CP866', 'CP932', 'CP949',
            'CP950', 'CP1029', 'CP1251', 'ASCII'
        ]
    })

    plugin.register_schema_definition('ServiceSmbUnixcharset', {
        'type': 'string',
        'enum': ['UTF-8', 'iso-8859-1', 'iso-8859-15', 'gb2312', 'EUC-JP', 'ASCII']
    })

    plugin.register_schema_definition('ServiceSmbLoglevel', {
        'type': 'string',
        'enum': list(LogLevel.__members__.keys())
    })

    plugin.register_schema_definition('ServiceSmbMinprotocol', {
        'type': 'string',
        'enum': PROTOCOLS
    })

    plugin.register_schema_definition('ServiceSmbMaxprotocol', {
        'type': 'string',
        'enum': PROTOCOLS
    })

    # Register providers
    plugin.register_provider("service.smb", SMBProvider)

    # Register tasks
    plugin.register_task_handler("service.smb.update", SMBConfigureTask)

    # Register debug hooks
    plugin.register_debug_hook(collect_debug)

    set_smb_sid()
    os.unlink('/var/db/samba4/registry.tdb')

    with contextlib.suppress(OSError):
        os.chmod('/var/db/samba4/private', 0o700)

    with contextlib.suppress(OSError):
        os.chmod('/var/db/samba4/private/msg.sock', 0o700)

    with contextlib.suppress(OSError):
        os.chmod('/var/db/samba4/winbindd_privileged', 0o750)

    node = ConfigNode('service.smb', dispatcher.configstore)
    configure_params(node.__getstate__(), dispatcher.call_sync('service.smb.ad_enabled'))
