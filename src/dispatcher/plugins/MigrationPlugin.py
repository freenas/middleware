#
# Copyright 2016 iXsystems, Inc.
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
import re
import ipaddress
import logging
import sqlite3
import datetime
import errno
import base64
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Cipher import AES
from collections import OrderedDict
from lib.system import system, SubprocessException
from freenas.serviced import push_status
from freenas.utils import query as q, extend
from lxml import etree
from bsd import sysctl
from freenas.dispatcher import Password
from freenas.dispatcher.rpc import RpcException, description, accepts, SchemaHelper as h
from task import (
    Task,
    ProgressTask,
    TaskException,
    TaskWarning,
    TaskDescription
)

logger = logging.getLogger('MigrationPlugin')
FREENAS93_DATABASE_PATH = '/data/freenas-v1.db'
PWENC_FILE_SECRET = '/data/pwenc_secret'
PWENC_BLOCK_SIZE = 32
PWENC_PADDING = '{'
PWENC_CHECK = 'Donuts!'
VERSION_FILE = '/etc/version'
GELI_KEYPATH = '/data/geli'
GELI_KEY_SLOT = 0
GELI_RECOVERY_SLOT = 1


class notifier(object):

    def is_freenas(self):
        if os.path.exists('/etc/version'):
            with open('/etc/version', 'r') as f:
                version = f.read().lower()
            if 'truenas' in version:
                return False
        return True

    def pwenc_get_secret(self):
        with open(PWENC_FILE_SECRET, 'rb') as f:
            secret = f.read()
        return secret

    def pwenc_encrypt(self, text):
        pad = lambda x: x + (PWENC_BLOCK_SIZE - len(x) % PWENC_BLOCK_SIZE) * PWENC_PADDING

        nonce = get_random_bytes(8)
        cipher = AES.new(
            self.pwenc_get_secret(),
            AES.MODE_CTR,
            counter=Counter.new(64, prefix=nonce),
        )
        encoded = base64.b64encode(nonce + cipher.encrypt(pad(text)))
        return encoded

    def pwenc_decrypt(self, encrypted=None):
        if not encrypted:
            return ""
        encrypted = base64.b64decode(encrypted)
        nonce = encrypted[:8]
        encrypted = encrypted[8:]
        cipher = AES.new(
            self.pwenc_get_secret(),
            AES.MODE_CTR,
            counter=Counter.new(64, prefix=nonce),
        )
        return cipher.decrypt(encrypted).decode('utf8').rstrip(PWENC_PADDING)


# Here we define all the constants
NOGROUP_ID = '8980c534-6a71-4bfb-bc72-54cbd5a186db'

SIZE_LOOKUP = {
    'KB': lambda x: int(x[:-2]) * 1024,
    'MB': lambda x: int(x[:-2]) * 1024 * 1024,
    'GB': lambda x: int(x[:-2]) * 1024 * 1024 * 1024,
    'TB': lambda x: int(x[:-2]) * 1024 * 1024 * 1024 * 1024
}

LAGG_PROTOCOL_MAP = {
    'failover': 'FAILOVER',
    # 'fec': 'ETHERCHANNEL',
    'lacp': 'LACP',
    'loadbalance': 'LOADBALANCE',
    'roundrobin': 'ROUNDROBIN',
    'none': 'NONE'
}


MEDIAOPT_MAP = {
    'full-duplex': 'FDX',
    'half-duplex': 'HDX'
}


CAPABILITY_MAP = {
    'rxcsum': ('RXCSUM',),
    'txcsum': ('TXCSUM',),
    'rxcsum6': ('RXCSUM_IPV6',),
    'txcsum6': ('TXCSUM_IPV6',),
    'tso': ('TSO4', 'TSO6'),
    'tso4': ('TSO4',),
    'tso6': ('TSO6',),
    'lro': ('LRO',)
}

CIFS_LOGLEVEL_MAP = {
    '0': 'NONE',
    '1': 'MINIMUM',
    '2': 'NORMAL',
    '3': 'FULL',
    '10': 'DEBUG',
}

PROTOCOL_CHOICES = {
    'http': ['HTTP'],
    'https': ['HTTPS'],
    'httphttps': ['HTTP', 'HTTPS'],
}

CRYPTO_TYPE = {
    1: 'CA_EXISTING',
    2: 'CA_INTERNAL',
    4: 'CA_INTERMEDIATE',
    8: 'CERT_EXISTING',
    16: 'CERT_INTERNAL',
    32: 'CERT_CSR'
}

FTP_TLS_OPTS_MAP = {
    'ftp_tls_opt_allow_client_renegotiations': 'ALLOW_CLIENT_RENEGOTIATIONS',
    'ftp_tls_opt_allow_dot_login': 'ALLOW_DOT_LOGIN',
    'ftp_tls_opt_allow_per_user': 'ALLOW_PER_USER',
    'ftp_tls_opt_common_name_required': 'COMMON_NAME_REQUIRED',
    'ftp_tls_opt_enable_diags': 'ENABLE_DIAGNOSTICS',
    'ftp_tls_opt_export_cert_data': 'EXPORT_CERTIFICATE_DATA',
    'ftp_tls_opt_no_cert_request': 'NO_CERTIFICATE_REQUEST',
    'ftp_tls_opt_no_empty_fragments': 'NO_EMPTY_FRAGMENTS',
    'ftp_tls_opt_no_session_reuse_required': 'NO_SESSION_REUSE_REQUIRED',
    'ftp_tls_opt_stdenvvars': 'STANDARD_ENV_VARS',
    'ftp_tls_opt_dns_name_required': 'DNS_NAME_REQUIRED',
    'ftp_tls_opt_ip_address_required': 'IP_ADDRESS_REQUIRED'
}


RSYNCD_MODULE_MODE_MAP = {
    'ro': 'READONLY',
    'wo': 'WRITEONLY',
    'rw': 'READWRITE'
}

# Only listing the valid directory service types for freenas10
DS_TYPE_LOOKUP = {
    1: 'winbind',  # 'ACTIVEDIRECTORY'
    2: 'ldap',  # 'LDAP'
    3: 'nis'  # 'NIS'
}

# Only listing the valid IDMAP types for freenas10
IDMAP_LOOKUP = {
    1: 'UNIX',  # 'idmap_ad'
    7: 'RID'
}


def get_table(query_string, dictionary=True):
    with sqlite3.connect(FREENAS93_DATABASE_PATH) as conn:
        cursor = conn.cursor()
        res = cursor.execute(query_string)
        header_names = [desc[0] for desc in res.description]
        data = res.fetchall()
        formatted_result = [
            {name: entry[i] for i, name in enumerate(header_names)} for entry in data
        ]
        if dictionary:
            formatted_result = {entry['id']: entry for entry in formatted_result}
        return formatted_result


def populate_user_obj(user, fn10_groups, fn9_user, fn9_groups, fn9_grpmem):

    if user is None:
        user = {}

    pubkeys = None
    try:
        with open('%s/.ssh/authorized_keys' % fn9_user['bsdusr_home'], 'r') as f:
            pubkeys = f.read().strip()
    except:
        pass

    try:
        grp = q.query(
            fn10_groups,
            ('gid', '=', fn9_groups[fn9_user['bsdusr_group_id']]['bsdgrp_gid']),
            single=True
        )['id']
    except:
        logger.debug(
            'Got exception whilst trying to lookup group for user: {0}'.format(fn9_user),
            exc_info=True
        )
        grp = NOGROUP_ID

    lmhash = nthash = password_changed_at = None
    if fn9_user['bsdusr_smbhash']:
        try:
            pieces = fn9_user['bsdusr_smbhash'].strip().split(':')
            lmhash = pieces[2]
            nthash = pieces[3]
            password_changed_at = datetime.datetime.fromtimestamp(int(pieces[5].split('-')[1], 16))
        except:
            pass

    try:
        aux_groups = [
            fn9_groups[item['bsdgrpmember_group_id']]['bsdgrp_gid']
            for item in fn9_grpmem.values() if item['bsdgrpmember_user_id'] == fn9_user['id']
        ]
        aux_groups = [item[0] for item in q.query(fn10_groups, ('gid', 'in', aux_groups), select=['id'])]
    except:
        logger.debug(
            'Got exception whilst trying to populate aux groups for user: {0}'.format(fn9_user),
            exc_info=True
        )
        aux_groups = []

    user.update({
        'uid': fn9_user['bsdusr_uid'],
        'sshpubkey': pubkeys,
        'username': fn9_user['bsdusr_username'],
        'group': grp,
        'groups': aux_groups,
        'unixhash': fn9_user['bsdusr_unixhash'],
        'full_name': fn9_user['bsdusr_full_name'],
        'password_disabled': bool(fn9_user['bsdusr_password_disabled']),
        'locked': bool(fn9_user['bsdusr_locked']),
        'shell': fn9_user['bsdusr_shell'],
        'home': fn9_user['bsdusr_home'],
        'sudo': bool(fn9_user['bsdusr_sudo']),
        'email': fn9_user['bsdusr_email'] or None,
        'lmhash': lmhash,
        'nthash': nthash,
        'password_changed_at': password_changed_at
    })
    return user


@description("Accounts (users and groups) migration task")
class AccountsMigrateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x users and grups to 10.x"

    def describe(self, accounts='all'):
        desc = "Migration of all FreeNAS 9.x users and groups to 10.x"
        if accounts == 'root':
            desc = "Migration of FreeNAS 9.x root user settings to 10.x"
        elif accounts == 'non-root':
            desc = "Migration of all (except root) FreeNAS 9.x users and groups to 10.x"
        return TaskDescription(desc)

    def run(self, accounts='all'):
        users = get_table('select * from account_bsdusers')
        root_user = users.pop(1)
        groups = get_table('select * from account_bsdgroups')
        grp_membership = get_table('select * from account_bsdgroupmembership')
        fn10_groups = None

        if accounts != 'non-root':
            # First lets create all the non buitlin groups in this system
            for g in filter(lambda x: x['bsdgrp_builtin'] == 0, groups.values()):
                try:
                    self.run_subtask_sync(
                        'group.create',
                        {
                            'name': g['bsdgrp_group'],
                            'gid': g['bsdgrp_gid'],
                            'sudo': bool(g['bsdgrp_sudo'])
                        },
                        validate=True
                    )
                except RpcException as err:
                    self.add_warning(TaskWarning(
                        err.code,
                        'Could not create group: {0} due to error: {1}'.format(g['bsdgrp_group'], err)
                    ))

            # Now lets add the root user's properties (password, etc)
            fn10_groups = list(self.dispatcher.call_sync('group.query'))
            fn10_root_user = self.dispatcher.call_sync(
                'user.query', [('uid', '=', 0)], {"single": True}
            )
            fn10_root_user = populate_user_obj(
                fn10_root_user, fn10_groups, root_user, groups, grp_membership
            )
            del fn10_root_user['builtin']
            del fn10_root_user['home']
            del fn10_root_user['uid']
            del fn10_root_user['username']
            del fn10_root_user['locked']
            del fn10_root_user['gid']
            fn10_root_user.pop('updated_at', None)
            fn10_root_user.pop('created_at', None)

            self.run_subtask_sync(
                'user.update', fn10_root_user['id'], fn10_root_user, validate=True
            )

        if accounts != 'root':
            if fn10_groups is None:
                fn10_groups = list(self.dispatcher.call_sync('group.query'))
            # Now rest of the users can be looped upon
            for u in filter(lambda x: x['bsdusr_builtin'] == 0, users.values()):
                try:
                    self.run_subtask_sync(
                        'user.create',
                        populate_user_obj(None, fn10_groups, u, groups, grp_membership),
                        validate=True
                    )
                except RpcException as err:
                    self.add_warning(TaskWarning(
                        err.code,
                        'Could not create user: {0} due to error: {1}'.format(u['bsdusr_username'], err)
                    ))


@description("Network migration task")
class NetworkMigrateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x network settings to 10.x"

    def describe(self):
        return TaskDescription("Migration of FreeNAS 9.x network settings to 10.x")

    def run(self):
        # Lets first get all the fn9 network config data we need
        fn9_globalconf = get_table('select * from network_globalconfiguration', dictionary=False)[0]
        fn9_interfaces = get_table('select * from network_interfaces')
        fn9_static_routes = get_table('select * from network_staticroute')
        fn9_vlaninfo = {
            v['vlan_vint']: v for v in get_table('select * from network_vlan').values()
        }

        fn9_lagg_membership = get_table('select * from network_lagginterfacemembers')
        fn9_lagginfo = {
            fn9_interfaces[laggy['lagg_interface_id']]['int_interface']: {
                'lagg_protocol': LAGG_PROTOCOL_MAP.get(laggy['lagg_protocol'], 'FAILOVER'),
                'lagg_members': [v for v in fn9_lagg_membership.values() if v['lagg_interfacegroup_id'] == laggy['id']]
            }
            for laggy in get_table('select * from network_lagginterface').values()
        }

        # get all aliases for all interfaces (nics, vlans, and laggs)
        fn9_aliases = {k: [] for k in fn9_interfaces.keys()}
        for v in get_table('select * from network_alias').values():
            fn9_aliases[v['alias_interface_id']].append(v)

        # Now get the fn10 data on network config and interfaces (needed to update interfaces, etc)
        fn10_interfaces = list(self.dispatcher.call_sync('network.interface.query'))

        # Now start with the conversion logic

        configured_nics = []
        lagg_member_nics = []
        # Migrating regular network interfaces
        for fn9_iface in fn9_interfaces.values():
            create_interface = True
            fn10_iface = q.query(
                fn10_interfaces, ('id', '=', fn9_iface['int_interface']), single=True
            )
            if fn10_iface:
                create_interface = False
                del fn10_iface['status']
                del fn10_iface['type']
                fn10_iface.pop('updated_at', None)
                fn10_iface.pop('created_at', None)
                configured_nics.append(fn9_iface['int_interface'])

            elif fn9_iface['int_interface'].lower().startswith('vlan'):
                fn10_iface = {
                    'type': 'VLAN',
                    'vlan': {
                        'parent': q.get(fn9_vlaninfo, f"{fn9_iface['int_interface']}.vlan_pint"),
                        'tag': q.get(fn9_vlaninfo, f"{fn9_iface['int_interface']}.vlan_tag")
                    }
                }
            elif fn9_iface['int_interface'].lower().startswith('lagg'):
                lagg_members = sorted(
                    q.get(fn9_lagginfo, f"{fn9_iface['int_interface']}.lagg_members", []),
                    key=lambda lg: lg['lagg_ordernum']
                )
                fn10_iface = {
                    'type': 'LAGG',
                    'lagg': {
                        'protocol': q.get(fn9_lagginfo, f"{fn9_iface['int_interface']}.lagg_protocol"),
                        'ports': [lg['lagg_physnic'] for lg in lagg_members]
                    }
                }
                lagg_member_nics.extend(fn10_iface['lagg']['ports'])
            else:
                self.add_warning(TaskWarning(
                    errno.ENXIO,
                    'Skipping FreeNAS 9.x network interface: {0} as it is not found'.format(
                        fn9_iface['int_interface']
                    )
                ))
                continue
            aliases = []
            if fn9_iface['int_ipv4address']:
                aliases.append({
                    'type': 'INET',
                    'address': fn9_iface['int_ipv4address'],
                    'netmask': int(fn9_iface['int_v4netmaskbit'])
                })
            if fn9_iface['int_ipv6address']:
                aliases.append({
                    'type': 'INET6',
                    'address': fn9_iface['int_ipv6address'],
                    'netmask': int(fn9_iface['int_v6netmaskbit'])
                })
            # Note: Currently not migrating fn9aliases 'alias_vip' field which
            # is the virtual ipv4 field and is only used by TrueNAS HA, please
            # do the same when we start doing TrueNAS 9.x-->10 migrations
            # this logic also applies to the 'alias_v4address_b' and 'alias_v6address_b'
            for alias in fn9_aliases.get(fn9_iface['id'], []):
                if alias['alias_v4address']:
                    aliases.append({
                        'type': 'INET',
                        'address': alias['alias_v4address'],
                        'netmask': int(alias['alias_v4netmaskbit'])
                    })

                if alias['alias_v6address']:
                    aliases.append({
                        'type': 'INET6',
                        'address': alias['alias_v6address'],
                        'netmask': int(alias['alias_v6netmaskbit'])
                    })

            fn10_iface.update({
                'name': fn9_iface['int_name'],
                'enabled': True,
                'dhcp': False if aliases else bool(fn9_iface['int_dhcp']),
                'aliases': aliases
            })
            m = re.search(r'mtu (\d+)', fn9_iface['int_options'])
            if m:
                fn10_iface['mtu'] = int(m.group(1))

            m = re.search(r'media (\w+)', fn9_iface['int_options'])
            if m:
                fn10_iface['media'] = m.group(1)

            m = re.search(r'mediaopt (\w+)', fn9_iface['int_options'])
            if m:
                opt = m.group(1)
                if opt in MEDIAOPT_MAP:
                    fn10_iface['mediaopts'] = [MEDIAOPT_MAP[opt]]

            # Try to read capabilities
            for k, v in CAPABILITY_MAP.items():
                if '-{0}'.format(k) in fn9_iface['int_options']:
                    l = fn10_iface.setdefault('capabilities', {}).setdefault('del', [])
                    l += v
                elif k in fn9_iface['int_options']:
                    l = fn10_iface.setdefault('capabilities', {}).setdefault('add', [])
                    l += v
            if create_interface:
                try:
                    self.run_subtask_sync('network.interface.create', fn10_iface, validate=True)
                except RpcException as err:
                    self.add_warning(TaskWarning(
                        err.code,
                        'Could not create interface: {0} due to err: {1}'.format(fn9_iface['int_interface'], err)
                    ))
            else:
                network_id = fn10_iface.pop('id')
                try:
                    self.run_subtask_sync(
                        'network.interface.update', network_id, fn10_iface, validate=True
                    )
                except RpcException as err:
                    self.add_warning(TaskWarning(
                        err.code,
                        'Could not configure network interface: {0} due to error: {1}'.format(
                            network_id, err
                        )
                    ))

        # I hate myself for doing this but I have no choices here
        # freenas 9 lagg interface member interfaces are/can be unconfigured in the gui
        # in which case I would need to set them to enabled here myself, or the lagg will
        # be migrated fine alright but its member interfaces will not be up :SAD:
        for unconf_interface in set(lagg_member_nics).difference(set(configured_nics)):
            fn10_iface = q.query(
                fn10_interfaces, ('id', '=', unconf_interface), single=True
            )
            if fn10_iface:
                network_id = fn10_iface.pop('id')
                fn10_iface['enabled'] = True
                try:
                    self.run_subtask_sync(
                        'network.interface.update', network_id, {'enabled': True}, validate=True
                    )
                except RpcException as err:
                    self.add_warning(TaskWarning(
                        err.code,
                        'Could not configure network interface: {0} due to error: {1}'.format(
                            network_id, err
                        )
                    ))
            else:
                self.add_warning(TaskWarning(
                    errno.ENXIO,
                    f'Skipping FreeNAS 9.x network interface: {unconf_interface} as it is not found'
                ))

        # Migrating hosts database
        for line in fn9_globalconf['gc_hosts'].split('\n'):
            line = line.strip()
            if line:
                ip, *names = line.split(' ')
                for name in names:
                    try:
                        self.run_subtask_sync(
                            'network.host.create', {'id': name, 'addresses': [ip]}, validate=True
                        )
                    except RpcException as err:
                        self.add_warning(TaskWarning(
                            err.code,
                            'Could not add host: {0}, ip: {1} due to error: {2}'.format(
                                name, ip, err
                            )
                        ))

        # Migrating static routes
        for route in fn9_static_routes.values():
            try:
                net = ipaddress.ip_network(route['sr_destination'])
            except ValueError as e:
                logger.debug("Invalid network {0}: {1}".format(route['sr_destination'], e))
                self.add_warning(TaskWarning(
                    errno.EINVAL, "Invalid network {0}: {1}".format(route['sr_destination'], e)
                ))
                continue

            try:
                self.run_subtask_sync(
                    'network.route.create',
                    {
                        'id': route['sr_description'],
                        'type': 'INET',
                        'network': str(net.network_address),
                        'netmask': net.prefixlen,
                        'gateway': route['sr_gateway'],
                    },
                    validate=True
                )
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Could not add network route: {0} due to error: {1}'.format(
                        route['sr_description'], err
                    )
                ))

        # Set the system hostname
        self.run_subtask_sync(
            'system.general.update',
            {'hostname': fn9_globalconf['gc_hostname'] + '.' + fn9_globalconf['gc_domain']},
            validate=True
        )

        # Finally migrate the global network config
        gc_nameservers = [
            fn9_globalconf['gc_nameserver' + x] for x in ['1', '2', '3']
            if fn9_globalconf['gc_nameserver' + x]
        ]
        self.run_subtask_sync(
            'network.config.update',
            {
                'autoconfigure': not bool(fn9_interfaces),
                'http_proxy': fn9_globalconf['gc_httpproxy'] or None,
                'gateway': {
                    'ipv4': fn9_globalconf['gc_ipv4gateway'] or None,
                    'ipv6': fn9_globalconf['gc_ipv6gateway'] or None
                },
                'dns': {'addresses': gc_nameservers},
                'dhcp': {
                    'assign_gateway': not bool(
                        fn9_globalconf['gc_ipv4gateway'] or fn9_globalconf['gc_ipv6gateway']
                    ),
                    'assign_dns': not bool(gc_nameservers)
                },
                'netwait': {
                    'enabled': bool(fn9_globalconf['gc_netwait_enabled']),
                    'addresses': list(filter(None, fn9_globalconf['gc_netwait_ip'].split(' ')))
                }
            }
        )

        # In case we have no interfaces manually configured in fn9 we need to retrigger the
        # networkd autoconfiguration stuff so do that below
        if not fn9_interfaces:
            try:
                for code, message in self.dispatcher.call_sync('networkd.configuration.configure_network', timeout=60):
                    self.add_warning(TaskWarning(code, message))
                self.dispatcher.call_sync('etcd.generation.generate_group', 'network')
            except RpcException as e:
                raise TaskException(errno.ENXIO, 'Cannot reconfigure interface: {0}'.format(str(e)))


@description("Storage volume migration task")
class StorageMigrateTask(Task):
    def __init__(self, dispatcher):
        super(StorageMigrateTask, self).__init__(dispatcher)
        self.__confxml = None
        self._notifier = notifier()
        self.fn10_disks = []

    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x storage volumes (pools)"

    def describe(self):
        return TaskDescription("Migration of FreeNAS 9.x storage volumes (pools)")

    def _geom_confxml(self):
        if self.__confxml is None:
            self.__confxml = etree.fromstring(sysctl.sysctlbyname('kern.geom.confxml'))
        return self.__confxml

    def identifier_to_device(self, ident):

        if not ident:
            return None

        doc = self._geom_confxml()

        search = re.search(r'\{(?P<type>.+?)\}(?P<value>.+)', ident)
        if not search:
            return None

        tp = search.group("type")
        value = search.group("value").strip()

        if tp == 'uuid':
            search = doc.xpath("//class[name = 'PART']/geom//config[rawuuid = '%s']/../../name" % value)
            if len(search) > 0:
                for entry in search:
                    if not entry.text.startswith('label'):
                        return entry.text
            return None

        elif tp == 'label':
            search = doc.xpath("//class[name = 'LABEL']/geom//provider[name = '%s']/../name" % value)
            if len(search) > 0:
                return search[0].text
            return None

        elif tp.startswith('serial'):
            if tp == 'serial_lunid':
                value = value.split('_')[0]
            dev = q.query(self.fn10_disks, ('serial', '=', value), single=True)
            return dev['status']['gdisk_name'] if dev else None

        elif tp == 'devicename':
            search = doc.xpath("//class[name = 'DEV']/geom[name = '%s']" % value)
            if len(search) > 0:
                return value
            return None

    def run(self):

        # Migrate disk settings
        fn9_disks = get_table('select * from storage_disk', dictionary=False)
        self.fn10_disks = list(self.dispatcher.call_sync('disk.query'))

        for fn9_disk in fn9_disks:
            dev = self.identifier_to_device(fn9_disk['disk_identifier'])
            if not dev:
                self.add_warning(TaskWarning(
                    errno.ENOENT,
                    'Identifier to device failed for {0}, skipping'.format(
                        fn9_disk['disk_identifier']
                    )
                ))
                continue
            newident = None
            newident_err = None
            try:
                newident = self.dispatcher.call_sync(
                    'disk.device_to_identifier', dev, fn9_disk['disk_serial'] or None
                )
            except RpcException as err:
                newident_err = err
            if newident is None:
                self.add_warning(TaskWarning(
                    errno.ENOENT,
                    'Skipping {0} since failed to convert it to id{1}'.format(
                        dev, ' due to error: {0}'.format(newident_err) if newident_err else ''
                    )
                ))
                continue

            fn10_disk = q.query(self.fn10_disks, ('id', '=', newident), single=True)

            if fn10_disk is None:
                self.add_warning(TaskWarning(
                    errno.ENOENT,
                    'Failed to lookup id: {0} for fn9 disk id: {1}, skipping'.format(newident, dev)
                ))
                continue

            del fn10_disk['serial']
            del fn10_disk['path']
            del fn10_disk['mediasize']
            del fn10_disk['status']
            fn10_disk.pop('created_at', None)
            fn10_disk.pop('updated_at', None)
            fn10_disk_name = fn10_disk.pop('name')
            fn10_disk.update({
                'smart': bool(fn9_disk['disk_togglesmart']),
                'smart_options': fn9_disk['disk_smartoptions'],
                'standby_mode': None if fn9_disk['disk_hddstandby'] == 'Always On' else int(fn9_disk['disk_hddstandby']),
                'acoustic_level': fn9_disk['disk_acousticlevel'].upper(),
                'apm_mode': None if fn9_disk['disk_advpowermgmt'] == 'Disabled' else int(fn9_disk['disk_advpowermgmt'])
            })
            try:
                self.run_subtask_sync('disk.update', fn10_disk.pop('id'), fn10_disk, validate=True)
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Could not update disk config for: {0} due to err: {1}'.format(fn10_disk_name, err)
                ))

        # Repopulate this list before we begin volume import
        # this is needed since I have a bunch of `del ` statements on
        # disks in here above, hence repopulating to ensure that `identifier_to_device`
        # returns proper values
        self.fn10_disks = list(self.dispatcher.call_sync('disk.query'))

        # Make a list of unimported fn10 volumes. This is to verify that the fn9 database volume
        # guid is not stale and if it is then to try and import the volume via name instead of guid
        # Unfortunately this would mean that any encrypted volume being migrated will ONLY be
        # imported via its name and not the guid
        fn10_unimported_vols = list(vol['id'] for vol in self.dispatcher.call_sync('volume.find'))

        # Importing fn9 volumes
        fn9_enc_disks = get_table('select * from storage_encrypteddisk')
        fn9_volumes = {
            k: extend(
                v,
                {'enc_disks': [enc for enc in fn9_enc_disks.values() if enc['encrypted_volume_id'] == v['id']]}
            ) for k, v in get_table('select * from storage_volume').items()
        }

        # Just keeping this here for reference for `vol_encrypt` field in fn9_volumes database
        # entry which states if the volume is encrypted or not and if it is encrypted then is it
        # passphrased or not
        # volencrypt_lookup = {
        #     0: 'Unencrypted',
        #     1: 'Encrypted, no passphrase',
        #     2: 'Encrypted, with passphrase'
        # }
        for fn9_volume in fn9_volumes.values():
            try:
                if fn9_volume['vol_encrypt'] > 1:
                    raise RpcException(
                        errno.EINVAL,
                        f"Cannot import passphrase encrypted volume: {fn9_volume['vol_name']}, please do so manually"
                    )

                key_contents = None
                encrypted_disks = []
                if fn9_volume['vol_encrypt']:
                    with open(f"/data/geli/{fn9_volume['vol_encryptkey']}.key", "rb") as key_file:
                        key_contents = base64.b64encode(key_file.read()).decode('utf-8')
                    for ed in fn9_volume['enc_disks']:
                        enc_disk = self.identifier_to_device(ed['encrypted_disk_id'])
                        if enc_disk:
                            encrypted_disks.append(os.path.join('/dev', enc_disk))

                self.run_subtask_sync(
                    'volume.import',
                    fn9_volume['vol_guid'] if fn9_volume['vol_guid'] in fn10_unimported_vols else fn9_volume['vol_name'],
                    None,
                    {},
                    {
                        'key': key_contents,
                        'disks': encrypted_disks
                    } if fn9_volume['vol_encrypt'] else {},
                    validate=True
                )
            except (OSError, RpcException) as err:
                self.add_warning(TaskWarning(
                    getattr(err, 'code', errno.EINVAL),
                    'Cannot import volume name: {0} GUID: {1} due to error: {2}'.format(
                        fn9_volume['vol_name'], fn9_volume['vol_guid'], err
                    )
                ))


@description("Shares migration task")
class ShareMigrateTask(Task):
    def __init__(self, dispatcher):
        super(ShareMigrateTask, self).__init__(dispatcher)
        self._notifier = notifier()
        self.fn10_datasets = []

    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x shares to 10.x"

    def describe(self):
        return TaskDescription("Migration of FreeNAS 9.x shares to 10.x")

    def get_type_and_path(self, path):
        return ('DATASET', path[len('/mnt/'):]) if q.query(
            self.fn10_datasets, ('mountpoint', '=', path), single=True
        ) else ('DIRECTORY', path)

    def run(self):
        # Generic stuff needed for all share migration
        self.fn10_datasets = list(self.dispatcher.call_sync('volume.dataset.query'))

        # Lets start with AFP shares
        fn9_afp_shares = get_table('select * from sharing_afp_share')
        for fn9_afp_share in fn9_afp_shares.values():
            ro_users, ro_groups, rw_users, rw_groups, users_allow, groups_allow, users_deny, groups_deny = [[] for _ in range(8)]
            for allow_item in fn9_afp_share['afp_rw'].split(','):
                allow_item = allow_item.strip(' ')
                if allow_item.startswith('@'):
                    groups_allow.append(allow_item[1:])
                elif allow_item:
                    users_allow.append(allow_item)
            for ro_item in fn9_afp_share['afp_ro'].split(','):
                ro_item = ro_item.strip(' ')
                if ro_item.startswith('@'):
                    ro_groups.append(ro_item[1:])
                elif ro_item:
                    ro_users.append(ro_item)
            for rw_item in fn9_afp_share['afp_rw'].split(','):
                rw_item = rw_item.strip(' ')
                if rw_item.startswith('@'):
                    rw_groups.append(rw_item[1:])
                elif rw_item:
                    rw_users.append(rw_item)
            for deny_item in fn9_afp_share['afp_deny'].split(','):
                deny_item = deny_item.strip(' ')
                if deny_item.startswith('@'):
                    groups_deny.append(deny_item[1:])
                elif deny_item:
                    users_deny.append(deny_item)
            hosts_deny = list(filter(None, fn9_afp_share['afp_hostsdeny'].split(' ')))
            hosts_allow = list(filter(None, fn9_afp_share['afp_hostsallow'].split(' ')))

            try:
                target_type, target_path = self.get_type_and_path(fn9_afp_share['afp_path'])
                self.run_subtask_sync(
                    'share.create',
                    {
                        'name': fn9_afp_share['afp_name'],
                        'description': fn9_afp_share['afp_comment'],
                        'enabled': True,
                        'immutable': False,
                        'type': 'afp',
                        'target_path': target_path,
                        'target_type': target_type,
                        'properties': {
                            '%type': 'ShareAfp',
                            'comment': fn9_afp_share['afp_comment'],
                            'read_only': False,
                            'time_machine': bool(fn9_afp_share['afp_timemachine']),
                            'zero_dev_numbers': bool(fn9_afp_share['afp_nodev']),
                            'no_stat': bool(fn9_afp_share['afp_nostat']),
                            'afp3_privileges': bool(fn9_afp_share['afp_upriv']),
                            'default_file_perms': {'value': int(fn9_afp_share['afp_fperm'])},
                            'default_directory_perms': {'value': int(fn9_afp_share['afp_dperm'])},
                            'ro_users': ro_users or None,
                            'ro_groups': ro_groups or None,
                            'rw_users': rw_users or None,
                            'rw_groups': rw_groups or None,
                            'users_allow': users_allow or None,
                            'users_deny': users_deny or None,
                            'groups_allow': groups_allow or None,
                            'groups_deny': groups_deny or None,
                            'hosts_allow': hosts_allow or None,
                            'hosts_deny': hosts_deny or None
                        }
                    },
                    validate=True
                )
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Cannot create AFP share: {0} due to error: {1}'.format(
                        fn9_afp_share['afp_name'], err
                    )
                ))

        # Now SMB shares
        fn9_smb_shares = get_table('select * from sharing_cifs_share')
        for fn9_smb_share in fn9_smb_shares.values():
            # Why does fn9 allow comma, space, or TAB delimiters in the same field!!!
            hosts_allow = list(filter(
                None,
                fn9_smb_share['cifs_hostsallow'].replace('\t', ',').replace(' ', ',').split(','))
            ) or None
            hosts_deny = list(filter(
                None,
                fn9_smb_share['cifs_hostsdeny'].replace('\t', ',').replace(' ', ',').split(','))
            ) or None
            # Note: 'cifs_storage_task_id' property of the share in fn9 is what tracked
            # whether the share was snapshotted or not and provided the 'windows shadow copies'
            # feature but in fn10 this has changed and is provided on a per share basis via the
            # 'previous_versions' boolean property which picks up *any* snapshots (if present)
            # of said dataset (or in the case of a shared directory it's parent dataset)

            # Also omitting 'cifs_auxsmbconf' property completely, if you know how to properly
            # parse it to fn10's `extra_parameters` object's key:value string format please do so
            try:
                target_type, target_path = self.get_type_and_path(fn9_smb_share['cifs_path'])
                self.run_subtask_sync(
                    'share.create',
                    {
                        'name': fn9_smb_share['cifs_name'],
                        'description': fn9_smb_share['cifs_comment'],
                        'enabled': True,
                        'immutable': False,
                        'type': 'smb',
                        'target_path': target_path,
                        'target_type': target_type,
                        'properties': {
                            '%type': 'ShareSmb',
                            'comment': fn9_smb_share['cifs_comment'],
                            'read_only': bool(fn9_smb_share['cifs_ro']),
                            'guest_ok': bool(fn9_smb_share['cifs_guestok']),
                            'guest_only': bool(fn9_smb_share['cifs_guestonly']),
                            'browseable': bool(fn9_smb_share['cifs_browsable']),
                            'recyclebin': bool(fn9_smb_share['cifs_recyclebin']),
                            'show_hidden_files': bool(fn9_smb_share['cifs_showhiddenfiles']),
                            'previous_versions': True,  # see comment above for explanation
                            'home_share': bool(fn9_smb_share['cifs_home']),
                            'vfs_objects': fn9_smb_share['cifs_vfsobjects'].split(','),
                            'hosts_allow': hosts_allow,
                            'hosts_deny': hosts_deny
                        }
                    },
                    validate=True
                )
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Cannot create SMB share: {0} due to error: {1}'.format(
                        fn9_smb_share['cifs_name'], err
                    )
                ))

        # Now NFS shares
        fn9_nfs_shares = get_table('select * from sharing_nfs_share')
        for nfs_path in get_table('select * from sharing_nfs_share_path').values():
            fn9_nfs_shares[nfs_path['share_id']]['path'] = nfs_path['path']

        for fn9_nfs_share in fn9_nfs_shares.values():
            try:
                target_type, target_path = self.get_type_and_path(fn9_nfs_share['path'])
                self.run_subtask_sync(
                    'share.create',
                    {
                        'name': fn9_nfs_share['path'],  # Had to use something
                        'description': fn9_nfs_share['nfs_comment'],
                        'enabled': True,
                        'immutable': False,
                        'type': 'nfs',
                        'target_path': target_path,
                        'target_type': target_type,
                        'properties': {
                            '%type': 'ShareNfs',
                            'alldirs': bool(fn9_nfs_share['nfs_alldirs']),
                            'read_only': bool(fn9_nfs_share['nfs_ro']),
                            'maproot_user': fn9_nfs_share['nfs_maproot_user'],
                            'maproot_group': fn9_nfs_share['nfs_maproot_group'],
                            'mapall_user': fn9_nfs_share['nfs_mapall_user'],
                            'mapall_group': fn9_nfs_share['nfs_mapall_group'],
                            'hosts': fn9_nfs_share['nfs_hosts'].replace('\t', ',').replace(' ', ',').split(','),
                            'security': [fn9_nfs_share['nfs_security']] if fn9_nfs_share['nfs_security'] else []
                        }
                    },
                    validate=True
                )
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Cannot create NFS share: {0} due to error: {1}'.format(
                        fn9_nfs_share['path'], err
                    )
                ))

        # Now WebDAV shares (que rico!)
        fn9_dav_shares = get_table('select * from sharing_webdav_share')
        for fn9_dav_share in fn9_dav_shares.values():
            try:
                target_type, target_path = self.get_type_and_path(fn9_dav_share['webdav_path'])
                self.run_subtask_sync(
                    'share.create',
                    {
                        'name': fn9_dav_share['webdav_name'],
                        'description': fn9_dav_share['webdav_comment'],
                        'enabled': True,
                        'immutable': False,
                        'type': 'webdav',
                        'target_path': target_path,
                        'target_type': target_type,
                        'properties': {
                            '%type': 'ShareWebdav',
                            'read_only': bool(fn9_dav_share['webdav_ro']),
                            'permission': bool(fn9_dav_share['webdav_perm'])
                        }
                    },
                    validate=True
                )
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Cannot create SMB share: {0} due to error: {1}'.format(
                        fn9_dav_share['webdav_name'], err
                    )
                ))

        # Lastly lets tackle the mamoth in the room: iSCSI

        # getting all the information from the fn9 database
        fn9_iscsitargets = get_table('select * from services_iscsitarget')
        fn9_iscsitargetauthcreds = get_table('select * from services_iscsitargetauthcredential')
        fn9_iscsitargetextents = get_table('select * from services_iscsitargetextent')
        fn9_iscsitargetgroups = get_table('select * from services_iscsitargetgroups')
        fn9_iscsitargetportals = get_table('select * from services_iscsitargetportal')
        fn9_iscsitargetportalips = get_table('select * from services_iscsitargetportalip')
        fn9_iscsitargettoextent_maps = get_table('select * from services_iscsitargettoextent')

        # Get non 'ALL' initiators
        fn9_initiators = {
            k: v
            for k, v in get_table('select * from services_iscsitargetauthorizedinitiator').items()
            if not v['iscsi_target_initiator_initiators'] == v['iscsi_target_initiator_auth_network'] == 'ALL'
        }

        # Here we go...
        for fn9_iscsitargetextent in fn9_iscsitargetextents.values():
            try:
                size = fn9_iscsitargetextent['iscsi_target_extent_filesize']
                if size == "0":
                    size = None
                else:
                    size = SIZE_LOOKUP.get(size[-2:], lambda x: int(x))(size)
                if bool(fn9_iscsitargetextent['iscsi_target_extent_legacy']):
                    vendor_id = 'FreeBSD'
                else:
                    vendor_id = 'FreeNAS' if self._notifier.is_freenas() else 'TrueNAS'
                serial = fn9_iscsitargetextent['iscsi_target_extent_serial']
                padded_serial = serial
                if not bool(fn9_iscsitargetextent['iscsi_target_extent_xen']):
                    for i in range(31 - len(serial)):
                        padded_serial += " "
                device_id = 'iSCSI Disk      {0}'.format(padded_serial)

                # Fix 'iscsi_target_extent_path' (example: 'zvol/js-fn-tank/iSCSITEST')
                extent_path = fn9_iscsitargetextent['iscsi_target_extent_path']
                if (
                    extent_path.startswith(('zvol/', '/mnt/')) and
                    fn9_iscsitargetextent['iscsi_target_extent_type'].upper() != "FILE"
                ):
                    extent_path = extent_path[5:]

                self.run_subtask_sync(
                    'share.create',
                    {
                        'name': fn9_iscsitargetextent['iscsi_target_extent_name'],
                        'description': fn9_iscsitargetextent['iscsi_target_extent_comment'],
                        'enabled': True,
                        'immutable': False,
                        'type': 'iscsi',
                        'target_path': extent_path,
                        'target_type': fn9_iscsitargetextent['iscsi_target_extent_type'].upper(),
                        'properties': {
                            '%type': 'ShareIscsi',
                            'serial': serial,
                            'naa': fn9_iscsitargetextent['iscsi_target_extent_naa'],
                            'size': size,
                            'block_size': fn9_iscsitargetextent['iscsi_target_extent_blocksize'],
                            'physical_block_size': bool(fn9_iscsitargetextent['iscsi_target_extent_pblocksize']),
                            'available_space_threshold': fn9_iscsitargetextent['iscsi_target_extent_avail_threshold'],
                            'read_only': bool(fn9_iscsitargetextent['iscsi_target_extent_ro']),
                            'xen_compat': bool(fn9_iscsitargetextent['iscsi_target_extent_xen']),
                            'tpc': bool(fn9_iscsitargetextent['iscsi_target_extent_insecure_tpc']),
                            'vendor_id': vendor_id,
                            'product_id': 'iSCSI Disk',
                            'device_id': device_id,
                            'rpm': fn9_iscsitargetextent['iscsi_target_extent_rpm']
                        }
                    },
                    validate=True
                )
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Cannot create iSCSI share: {0} due to error: {1}'.format(
                        fn9_iscsitargetextent['iscsi_target_extent_name'], err
                    )
                ))

        # required mappings
        authgroup_to_portal_map = {}
        authgroup_to_target_map = {}
        target_to_portal_map = {}

        for auth in fn9_iscsitargetauthcreds.values():
            auth.update({
                'auth_methods': {
                    'None': {'portal_ids': [], 'target_ids': []},
                    'CHAP': {'portal_ids': [], 'target_ids': []},
                    'CHAP Mutual': {'portal_ids': [], 'target_ids': []},
                },
                'initiators': [],
                'networks': []
            })
            for x in fn9_iscsitargetportals.values():
                if x['iscsi_target_portal_discoveryauthgroup'] == auth['iscsi_target_auth_tag']:
                    auth['auth_methods'][x['iscsi_target_portal_discoveryauthmethod']]['portal_ids'].append(x['id'])

            for x in fn9_iscsitargetgroups.values():
                if x['iscsi_target_authgroup'] == auth['iscsi_target_auth_tag']:
                    auth['auth_methods'][x['iscsi_target_authtype']]['target_ids'].append(x['id'])
                    auth_initiator9 = fn9_initiators.get(x['iscsi_target_initiatorgroup_id'])
                    if auth_initiator9:
                        for initiator in filter(
                            lambda val: val and val != 'ALL',
                            auth_initiator9['iscsi_target_initiator_initiators'].replace('\n', ',').replace(' ', ',').split(',')
                        ):
                            auth['initiators'].append(initiator)
                        for network in filter(
                            lambda val: val and val != 'ALL',
                            auth_initiator9['iscsi_target_initiator_auth_network'].replace('\n', ',').replace(' ', ',').split(',')
                        ):
                            auth['networs'].append(network)

        # Now lets make them auth groups, portals, and targets
        for fn9_targetauthcred in fn9_iscsitargetauthcreds.values():
            # Note I am deliberately dropping group id and letting fn10 generate it
            # this is due to the way I have to construct multiple auth groups per
            # iscsi auth type that they are used with.
            # i.e. in fn9 that same auth credential entry with 'group id'=1 can be used
            # 'CHAP', 'CHAP_MUTUAL', and 'NONE' in fn9's iscsi portals, BUT, in fn10
            # we need to create a different auth group entry per auth type in it
            def create_auth_group(auth_type='NONE', fn9_targetauthcred=fn9_targetauthcred):
                try:
                    return self.run_subtask_sync(
                        'share.iscsi.auth.create',
                        {
                            'description':
                                'Migrated freenas 9.x auth group id: {0}, auth_type: {1}'.format(
                                    fn9_targetauthcred['iscsi_target_auth_tag'], auth_type
                                ),
                            'type': auth_type,
                            'users': [{
                                'name': fn9_targetauthcred['iscsi_target_auth_user'],
                                'secret': self._notifier.pwenc_decrypt(
                                    fn9_targetauthcred['iscsi_target_auth_secret']
                                ) if fn9_targetauthcred['iscsi_target_auth_secret'] else None,
                                'peer_name': fn9_targetauthcred['iscsi_target_auth_peeruser'],
                                'peer_secret': self._notifier.pwenc_decrypt(
                                    fn9_targetauthcred['iscsi_target_auth_peersecret']
                                ) if fn9_targetauthcred['iscsi_target_auth_peersecret'] else None
                            }],
                            'initiators': fn9_targetauthcred['initiators'] or None,
                            'networks': fn9_targetauthcred['networks'] or None
                        },
                        validate=True
                    )
                except RpcException as err:
                    self.add_warning(TaskWarning(
                        err.code,
                        'Cannot create iSCSI auth group: {0}, auth_type: {1}, error: {2}'.format(
                            fn9_targetauthcred['iscsi_target_auth_tag'], auth_type, err
                        )
                    ))
            auth_created = False
            for auth_type, id_vals in fn9_targetauthcred['auth_methods'].items():
                if id_vals['portal_ids'] or id_vals['target_ids']:
                    auth_created = True
                    auth_id = create_auth_group(auth_type=auth_type.upper().replace(' ', '_'))
                    for portal_id in id_vals['portal_ids']:
                        authgroup_to_portal_map[portal_id] = auth_id
                    for target_id in id_vals['target_ids']:
                        authgroup_to_target_map[target_id] = auth_id
            if not auth_created:
                # This meant that the auth group was made but nvere linked to any portal or
                # target so lets just make it with 'NONE' authmethod
                create_auth_group(auth_type='NONE')

        for fn9_iscsitargetportal in fn9_iscsitargetportals.values():
            try:
                portal_id = self.run_subtask_sync(
                    'share.iscsi.portal.create',
                    {
                        'tag': fn9_iscsitargetportal['iscsi_target_portal_tag'],
                        'description': fn9_iscsitargetportal['iscsi_target_portal_comment'],
                        'discovery_auth_group': authgroup_to_portal_map.get(
                            fn9_iscsitargetportal['id'], None
                        ),
                        'listen': [
                            {
                                'address': p['iscsi_target_portalip_ip'],
                                'port': p['iscsi_target_portalip_port']
                            }
                            for p in fn9_iscsitargetportalips.values()
                            if p['iscsi_target_portalip_portal_id'] == fn9_iscsitargetportal['id']
                        ]
                    },
                    validate=True
                )
                for x in fn9_iscsitargetgroups.values():
                    if x['iscsi_target_portalgroup_id'] == fn9_iscsitargetportal['id']:
                        target_to_portal_map[x['iscsi_target_id']] = portal_id

            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Cannot create iSCSI portal: {0} due to error: {1}'.format(
                        fn9_iscsitargetportal['iscsi_target_portal_tag'], err
                    )
                ))

        for fn9_iscsitarget in fn9_iscsitargets.values():
            try:
                auth_group = authgroup_to_target_map.get(fn9_iscsitarget['id'])
                if auth_group is None:
                    # If this is none that means that we still need to map the initiators
                    # by creating an auth group just for the 'initiators' and 'networks' fields
                    for x in fn9_iscsitargetgroups.values():
                        if x['iscsi_target_id'] == fn9_iscsitarget['id']:
                            initiator_obj = fn9_initiators.get(x['iscsi_target_initiatorgroup_id'])
                            if initiator_obj:
                                target_initiators = []
                                target_networks = []
                                for initiator in filter(
                                    lambda val: val and val != 'ALL',
                                    initiator_obj['iscsi_target_initiator_initiators'].replace('\n', ',').replace(' ', ',').split(',')
                                ):
                                    target_initiators.append(initiator)
                                for network in filter(
                                    lambda val: val and val != 'ALL',
                                    initiator_obj['iscsi_target_initiator_auth_network'].replace('\n', ',').replace(' ', ',').split(',')
                                ):
                                    target_networks.append(network)
                                try:
                                    auth_group = self.run_subtask_sync(
                                        'share.iscsi.auth.create',
                                        {
                                            'description': '{0} auth group for initiators and networks only'.format(fn9_iscsitarget['iscsi_target_alias']),
                                            'type': 'NONE',
                                            'initiators': target_initiators or None,
                                            'networks': target_networks or None,
                                        },
                                        validate=True
                                    )
                                except RpcException as err:
                                    self.add_warning(TaskWarning(
                                        err.code,
                                        "Cannot create iSCSI auth group for {0} target's initiators and networks, error: {2}".format(
                                            fn9_iscsitarget['iscsi_target_name'], err
                                        )
                                    ))
                            break

                self.run_subtask_sync(
                    'share.iscsi.target.create',
                    {
                        'id': fn9_iscsitarget['iscsi_target_name'],
                        'description': fn9_iscsitarget['iscsi_target_alias'],
                        'auth_group': auth_group or 'no-authentication',
                        'portal_group': target_to_portal_map.get(fn9_iscsitarget['id'], 'default'),
                        'extents': [
                            {
                                'name': fn9_iscsitargetextents[x['iscsi_extent_id']]['iscsi_target_extent_name'],
                                'number': x['iscsi_lunid']
                            }
                            for x in fn9_iscsitargettoextent_maps.values()
                            if x['iscsi_target_id'] == fn9_iscsitarget['id']
                        ]
                    },
                    validate=True
                )
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Cannot create iSCSI target: {0} due to error: {1}'.format(
                        fn9_iscsitarget['iscsi_target_name'], err
                    )
                ))


@description("Service settings migration task")
class ServiceMigrateTask(Task):
    def __init__(self, dispatcher):
        super(ServiceMigrateTask, self).__init__(dispatcher)
        self._notifier = notifier()

    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x services' settings to 10.x"

    def describe(self):
        return TaskDescription("Migration of FreeNAS 9.x services' settings to 10.x")

    def run(self):
        # Generic stuff needed for all service migrations
        fn10_certs_and_cas = list(self.dispatcher.call_sync('crypto.certificate.query'))
        fn9_cas = get_table('select * from system_certificateauthority')
        fn9_certs = get_table('select * from system_certificate')
        # dict containing service enable flags for all services
        fn9_services = {
            srv['srv_service']: srv for srv in get_table('select * from services_services').values()
        }

        fn10_services = list(self.dispatcher.call_sync('service.query'))

        # Migrating iSCSI service
        fn9_iscsi = get_table('select * from services_iscsitargetglobalconfiguration', dictionary=False)[0]
        try:
            # Note: `iscsi_alua` property of fn9 is not there in fn10 so not touching it below
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "iscsi"), single=True)['id'],
                {'config': {
                    'type': 'ServiceIscsi',
                    'enable': bool(fn9_services['iscsitarget']['srv_enable']),
                    'base_name': fn9_iscsi['iscsi_basename'],
                    'pool_space_threshold': fn9_iscsi['iscsi_pool_avail_threshold'],
                    'isns_servers': list(filter(None, fn9_iscsi['iscsi_isns_servers'].split(' ')))
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code,
                'Could not migrate iSCSI service settings due to err: {0}'.format(err)
            ))

        # Migrating AFP service
        fn9_afp = get_table('select * from services_afp', dictionary=False)[0]
        try:
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "afp"), single=True)['id'],
                {'config': {
                    'type': 'ServiceAfp',
                    'enable': bool(fn9_services['afp']['srv_enable']),
                    'guest_enable': bool(fn9_afp['afp_srv_guest']),
                    'guest_user': fn9_afp['afp_srv_guest_user'],
                    'bind_addresses': [
                        i.strip() for i in fn9_afp['afp_srv_bindip'].split(',')
                        if (i and not i.isspace())
                    ] or None,
                    'connections_limit': fn9_afp['afp_srv_connections_limit'],
                    'homedir_enable': True if fn9_afp['afp_srv_homedir_enable'] in ('True', 1) else False,
                    'homedir_path': fn9_afp['afp_srv_homedir'] or None,
                    'homedir_name': fn9_afp['afp_srv_homename'] or None,
                    'dbpath': fn9_afp['afp_srv_dbpath'] or None,
                    'auxiliary': fn9_afp['afp_srv_global_aux'] or None
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate AFP service settings due to err: {0}'.format(err)
            ))

        # Migrating SMB service
        fn9_smb = get_table('select * from services_cifs', dictionary=False)[0]
        try:
            smbconfig = {
                'type': 'ServiceSmb',
                'enable': bool(fn9_services['cifs']['srv_enable']),
                'netbiosname': [fn9_smb['cifs_srv_netbiosname']],
                'workgroup': fn9_smb['cifs_srv_workgroup'],
                'description': fn9_smb['cifs_srv_description'],
                'dos_charset': fn9_smb['cifs_srv_doscharset'],
                'unix_charset': fn9_smb['cifs_srv_unixcharset'],
                'log_level': CIFS_LOGLEVEL_MAP.get(str(fn9_smb['cifs_srv_loglevel']), 'MINIMUM'),
                'local_master': bool(fn9_smb['cifs_srv_localmaster']),
                'domain_logons': bool(fn9_smb['cifs_srv_domain_logons']),
                'time_server': bool(fn9_smb['cifs_srv_timeserver']),
                'guest_user': fn9_smb['cifs_srv_guest'],
                'filemask': {'value': int(fn9_smb['cifs_srv_filemask'])} if fn9_smb['cifs_srv_filemask'] else None,
                'dirmask': {'value': int(fn9_smb['cifs_srv_dirmask'])} if fn9_smb['cifs_srv_dirmask'] else None,
                'unixext': bool(fn9_smb['cifs_srv_unixext']),
                'zeroconf': bool(fn9_smb['cifs_srv_zeroconf']),
                'hostlookup': bool(fn9_smb['cifs_srv_hostlookup']),
                'max_protocol': fn9_smb['cifs_srv_max_protocol'],
                'execute_always': bool(fn9_smb['cifs_srv_allow_execute_always']),
                'obey_pam_restrictions': bool(fn9_smb['cifs_srv_obey_pam_restrictions']),
                'bind_addresses': fn9_smb['cifs_srv_bindip'].split(',') if fn9_smb['cifs_srv_bindip'] else None,
                'auxiliary': fn9_smb['cifs_srv_smb_options'] or None,
                'sid': fn9_smb['cifs_SID']
            }
            if fn9_smb['cifs_srv_min_protocol']:
                smbconfig.update({'min_protocol': fn9_smb['cifs_srv_min_protocol']})
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "smb"), single=True)['id'],
                {'config': smbconfig},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate SMB service settings due to err: {0}'.format(err)
            ))

        # Migrating NFS service
        fn9_nfs = get_table('select * from services_nfs', dictionary=False)[0]
        try:
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "nfs"), single=True)['id'],
                {'config': {
                    'type': 'ServiceNfs',
                    'enable': bool(fn9_services['nfs']['srv_enable']),
                    'servers': fn9_nfs['nfs_srv_servers'],
                    'udp': bool(fn9_nfs['nfs_srv_udp']),
                    'nonroot': bool(fn9_nfs['nfs_srv_allow_nonroot']),
                    'v4': bool(fn9_nfs['nfs_srv_v4']),
                    'v4_kerberos': bool(fn9_nfs['nfs_srv_v4_krb']),
                    'bind_addresses': fn9_nfs['nfs_srv_bindip'].split(',') if fn9_nfs['nfs_srv_bindip'] else None,
                    'mountd_port': fn9_nfs['nfs_srv_mountd_port'],
                    'rpcstatd_port': fn9_nfs['nfs_srv_rpcstatd_port'],
                    'rpclockd_port': fn9_nfs['nfs_srv_rpclockd_port']
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate NFS service settings due to err: {0}'.format(err)
            ))

        # Migrating WebDAV service
        fn9_dav = get_table('select * from services_webdav', dictionary=False)[0]
        try:
            webdav_cert = None
            if fn9_dav['webdav_certssl_id']:
                webdav_cert9 = fn9_certs.get(fn9_dav['webdav_certssl_id'], {})
                webdav_cert = q.query(
                    fn10_certs_and_cas,
                    ('name', '=', webdav_cert9.get('cert_name')),
                    single=True
                )
                if webdav_cert is None:
                    self.add_warning(TaskWarning(
                        err.code,
                        'Could not find the certificate for setting up secure WebDAV service'
                    ))
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "webdav"), single=True)['id'],
                {'config': {
                    'type': 'ServiceWebdav',
                    'enable': bool(fn9_services['webdav']['srv_enable']),
                    'protocol': PROTOCOL_CHOICES[fn9_dav['webdav_protocol']],
                    'http_port': fn9_dav['webdav_tcpport'],
                    'https_port': fn9_dav['webdav_tcpportssl'],
                    'password': {
                        '$password': self._notifier.pwenc_decrypt(fn9_dav['webdav_password'])
                    },
                    'authentication': fn9_dav['webdav_htauth'].upper(),
                    'certificate': webdav_cert['id'] if webdav_cert else None
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate WebDAV service settings due to err: {0}'.format(err)
            ))

        # Migrating SSHD service
        fn9_sshd = get_table('select * from services_ssh', dictionary=False)[0]
        try:
            for keytype in ('rsa', 'dsa', 'ecdsa', 'ed25519'):
                privkey = fn9_sshd['ssh_host_{0}_key'.format(keytype)]
                pubkey = fn9_sshd['ssh_host_{0}_key_pub'.format(keytype)]
                certfile = fn9_sshd['ssh_host_{0}_key_cert_pub'.format(keytype)]
                if pubkey and privkey:
                    self.dispatcher.configstore.set(f'service.sshd.keys.{keytype}.private', privkey)
                    self.dispatcher.configstore.set(f'service.sshd.keys.{keytype}.public', pubkey)
                    self.dispatcher.configstore.set(
                        f'serivce.sshd.keys.{keytype}.certificate',
                        certfile or None
                    )
            # Note not sending etcd regeneration event for sshd_keys because the service config
            # task below will already do that so lets just rely on that
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "sshd"), single=True)['id'],
                {'config': {
                    'type': 'ServiceSshd',
                    'enable': bool(fn9_services['ssh']['srv_enable']),
                    'port': fn9_sshd['ssh_tcpport'],
                    'permit_root_login': bool(fn9_sshd['ssh_rootlogin']),
                    'allow_gssapi_auth': bool(fn9_sshd['ssh_kerberosauth']),
                    'allow_password_auth': bool(fn9_sshd['ssh_passwordauth']),
                    'compression': bool(fn9_sshd['ssh_compression']),
                    'sftp_log_level': fn9_sshd['ssh_sftp_log_level'] or 'ERROR',
                    'sftp_log_facility': fn9_sshd['ssh_sftp_log_facility'] or 'AUTH',
                    'auxiliary': fn9_sshd['ssh_options'] or None
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate SSHD service settings due to err: {0}'.format(err)
            ))

        # Migrating DynDNS service
        fn9_dyndns = get_table('select * from services_dynamicdns', dictionary=False)[0]
        try:
            # workaround bogus default entry in 9.10 databse
            if fn9_dyndns['ddns_provider'] == 'dyndns':
                fn9_dyndns['ddns_provider'] = 'dyndns@dyndns.org'
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "dyndns"), single=True)['id'],
                {'config': {
                    'type': 'ServiceDyndns',
                    'enable': bool(fn9_services['dynamicdns']['srv_enable']),
                    'provider': fn9_dyndns['ddns_provider'] or None,
                    'ipserver': fn9_dyndns['ddns_ipserver'] or None,
                    'domains': fn9_dyndns['ddns_domain'].split(',') if fn9_dyndns['ddns_domain'] else [],
                    'username': fn9_dyndns['ddns_username'],
                    'password': {
                        '$password': self._notifier.pwenc_decrypt(fn9_dyndns['ddns_password'])
                    },
                    'update_period': int(fn9_dyndns['ddns_updateperiod']) if fn9_dyndns['ddns_updateperiod'] else None,
                    'force_update_period': int(fn9_dyndns['ddns_fupdateperiod']) if fn9_dyndns['ddns_fupdateperiod'] else None,
                    'auxiliary': fn9_dyndns['ddns_options']
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code,
                'Could not migrate Dynamic DNS service settings due to err: {0}'.format(err)
            ))

        fn9_ftp = get_table('select * from services_ftp', dictionary=False)[0]
        try:
            ftp_cert = None
            if fn9_ftp['ftp_ssltls_certificate_id']:
                ftp_cert9 = fn9_certs.get(fn9_ftp['ftp_ssltls_certificate_id'], {})
                ftp_cert = q.query(
                    fn10_certs_and_cas,
                    ('name', '=', ftp_cert9.get('cert_name')),
                    single=True
                )
                if ftp_cert is None:
                    self.add_warning(TaskWarning(
                        err.code,
                        'Could not find the certificate for setting up secure FTP service'
                    ))
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "ftp"), single=True)['id'],
                {'config': {
                    'type': 'ServiceFtp',
                    'enable': bool(fn9_services['ftp']['srv_enable']),
                    'port': fn9_ftp['ftp_port'],
                    'max_clients': fn9_ftp['ftp_clients'],
                    'ip_connections': fn9_ftp['ftp_ipconnections'],
                    'login_attempt': fn9_ftp['ftp_loginattempt'],
                    'timeout': fn9_ftp['ftp_timeout'],
                    'root_login': bool(fn9_ftp['ftp_rootlogin']),
                    'anonymous_path': fn9_ftp['ftp_anonpath'],
                    'only_anonymous': bool(fn9_ftp['ftp_onlyanonymous']),
                    'only_local': bool(fn9_ftp['ftp_onlylocal']),
                    'display_login': fn9_ftp['ftp_banner'] or None,
                    'filemask': {'value': int(fn9_ftp['ftp_filemask'])},
                    'dirmask': {'value': int(fn9_ftp['ftp_dirmask'])},
                    'fxp': bool(fn9_ftp['ftp_fxp']),
                    'resume': bool(fn9_ftp['ftp_resume']),
                    'chroot': bool(fn9_ftp['ftp_defaultroot']),
                    'ident': bool(fn9_ftp['ftp_ident']),
                    'reverse_dns': bool(fn9_ftp['ftp_reversedns']),
                    'masquerade_address': fn9_ftp['ftp_masqaddress'] or None,
                    'passive_ports_min': fn9_ftp['ftp_passiveportsmin'] or None,  # fn9 sets this as 0 for none hence doing this 'or'
                    'passive_ports_max': fn9_ftp['ftp_passiveportsmax'] or None,
                    'local_up_bandwidth': fn9_ftp['ftp_localuserbw'] or None,
                    'local_down_bandwidth': fn9_ftp['ftp_localuserdlbw'] or None,
                    'anon_up_bandwidth': fn9_ftp['ftp_anonuserbw'] or None,
                    'anon_down_bandwidth': fn9_ftp['ftp_anonuserdlbw'] or None,
                    'tls': bool(fn9_ftp['ftp_tls']),
                    'tls_policy': fn9_ftp['ftp_tls_policy'].upper(),
                    'tls_options': [
                        v for k, v in FTP_TLS_OPTS_MAP.items() if fn9_ftp[k] not in ['False', 0]
                    ],
                    'tls_ssl_certificate': ftp_cert['id'] if ftp_cert else None,
                    'auxiliary': fn9_ftp['ftp_options'] or None
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate FTP service settings due to err: {0}'.format(err)
            ))

        fn9_lldp = get_table('select * from services_lldp', dictionary=False)[0]
        try:
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "lldp"), single=True)['id'],
                {'config': {
                    'type': 'ServiceLldp',
                    'enable': bool(fn9_services['lldp']['srv_enable']),
                    'save_description': bool(fn9_lldp['lldp_intdesc']),
                    'country_code': fn9_lldp['lldp_country'] or None,
                    'location': fn9_lldp['lldp_location'] or None,
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate LLDP service settings due to err: {0}'.format(err)
            ))

        # Migrating RSYNCD service and modules
        fn9_rsyncd = get_table('select * from services_rsyncd', dictionary=False)[0]
        try:
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "rsyncd"), single=True)['id'],
                {'config': {
                    'type': 'ServiceRsyncd',
                    'enable': bool(fn9_services['rsync']['srv_enable']),
                    'port': fn9_rsyncd['rsyncd_port'],
                    'auxiliary': fn9_rsyncd['rsyncd_auxiliary']
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate RSYNCD service settings due to err: {0}'.format(err)
            ))

        fn9_rsyncd_mods = get_table('select * from services_rsyncmod')
        for rsyncd_mod in fn9_rsyncd_mods.values():
            try:
                self.run_subtask_sync(
                    'rsyncd.module.create',
                    {
                        'name': rsyncd_mod['rsyncmod_name'],
                        'description': rsyncd_mod['comment'],
                        'path': rsyncd_mod['path'],
                        'mode': RSYNCD_MODULE_MODE_MAP[rsyncd_mod['rsyncmod_mode']],
                        'max_connections': rsyncd_mod['rsyncmod_maxconn'] or None,
                        'user': rsyncd_mod['rsyncmod_user'],
                        'group': rsyncd_mod['rsyncmod_group'],
                        'hosts_allow': list(filter(
                            None, rsyncd_mod['rsyncmod_hostsallow'].replace('\t', ',').replace(' ', ',').split(','))
                        ) or None,
                        'hosts_deny': list(filter(
                            None, rsyncd_mod['rsyncmod_hostsdeny'].replace('\t', ',').replace(' ', ',').split(','))
                        ) or None,
                        'auxiliary': rsyncd_mod['rsyncmod_auxiliary'] or None,
                    },
                    validate=True
                )
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Could not migrate rsyncd module: {0} due to err: {1}'.format(
                        rsyncd_mod['rsyncmod_name'], err
                    )
                ))

        # Migrating SNMP service
        fn9_snmp = get_table('select * from services_snmp', dictionary=False)[0]
        try:
            # Note currently the snmp v3 password (fn9 property "snmp_v3_password") is not
            # encrypted in the fn9 database, if this changes make it go through notifier's
            # pwenc_decrypt routine before handing it to the task (see other password examples)
            snmp_config = {
                'type': 'ServiceSnmp',
                'enable': bool(fn9_services['snmp']['srv_enable']),
                'location': fn9_snmp['snmp_location'] or None,
                'contact': fn9_snmp['snmp_contact'] or None,
                'community': fn9_snmp['snmp_community'] or None,
                'v3': bool(fn9_snmp['snmp_v3']),
                'v3_username': fn9_snmp['snmp_v3_username'] or None,
                'v3_password': {
                    '$password': fn9_snmp['snmp_v3_password']
                } if fn9_snmp['snmp_v3_password'] else None,
                'v3_auth_type': fn9_snmp['snmp_v3_authtype'],
                'v3_privacy_passphrase': fn9_snmp['snmp_v3_privpassphrase'] or None,
                'auxiliary': fn9_snmp['snmp_options'] or None,
            }
            if fn9_snmp['snmp_v3_privproto']:
                snmp_config.update({'v3_privacy_protocol': fn9_snmp['snmp_v3_privproto']})
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "snmp"), single=True)['id'],
                {'config': snmp_config},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate SNMP service settings due to err: {0}'.format(err)
            ))

        # Migrating TFTP service
        fn9_tftp = get_table('select * from services_tftp', dictionary=False)[0]
        try:
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "tftpd"), single=True)['id'],
                {'config': {
                    'type': 'ServiceTftpd',
                    'enable': bool(fn9_services['tftp']['srv_enable']),
                    'port': fn9_tftp['tftp_port'],
                    'path': fn9_tftp['tftp_directory'],
                    'allow_new_files': bool(fn9_tftp['tftp_newfiles']),
                    'username': fn9_tftp['tftp_username'],
                    'umask': {'value': int(fn9_tftp['tftp_umask'])},
                    'auxiliary': fn9_tftp['tftp_options'] or None
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate TFTP service settings due to err: {0}'.format(err)
            ))

        # Migrating UPS (YAY LAST SERVICE TO MIGRATE!!!)
        fn9_ups = get_table('select * from services_ups', dictionary=False)[0]
        try:
            self.run_subtask_sync(
                'service.update',
                q.query(fn10_services, ("name", "=", "ups"), single=True)['id'],
                {'config': {
                    'type': 'ServiceUps',
                    'enable': bool(fn9_services['ups']['srv_enable']),
                    'mode': fn9_ups['ups_mode'].upper(),
                    'identifier': fn9_ups['ups_identifier'],
                    'remote_host': fn9_ups['ups_remotehost'] or None,
                    'remote_port': fn9_ups['ups_remoteport'],
                    'driver': fn9_ups['ups_driver'] or None,
                    'driver_port': fn9_ups['ups_port'] or None,
                    'description': fn9_ups['ups_description'] or None,
                    'shutdown_mode': fn9_ups['ups_shutdown'].upper(),
                    'shutdown_timer': fn9_ups['ups_shutdowntimer'],
                    'monitor_user': fn9_ups['ups_monuser'],
                    'monitor_password': {
                        '$password': self._notifier.pwenc_decrypt(fn9_ups['ups_monpwd'])
                    },
                    'allow_remote_connections': bool(fn9_ups['ups_rmonitor']),
                    'powerdown': True if fn9_ups['ups_powerdown'] in ['True', 1] else False,
                    'auxiliary': fn9_ups['ups_options'] or None
                }},
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate UPS service settings due to err: {0}'.format(err)
            ))

        # Template to use for adding future service migrations
        # Migrating FOO service
        # fn9_foo = get_table('select * from services_foo', dictionary=False)[0]
        # try:
        #     self.run_subtask_sync(
        #         'service.update',
        #         q.query(fn10_services, ("name", "=", "foo"), single=True)['id'],
        #         {'config': {
        #             'enable': bool(fn9_services['foo']['srv_enable'])
        #         }},
        #         validate=True
        #     )
        # except RpcException as err:
        #     self.add_warning(TaskWarning(
        #         err.code, 'Could not migrate FOO service settings due to err: {0}'.format(err)
        #     ))


@description("System (general & advanced) settings migration task")
class SystemMigrateTask(Task):
    def __init__(self, dispatcher):
        super(SystemMigrateTask, self).__init__(dispatcher)
        self._notifier = notifier()

    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x system settings to 10"

    def describe(self):
        return TaskDescription("Migration of FreeNAS 9.x system settings to 10")

    def run(self):
        # first lets get all the fn9 data that we need
        fn9_sys_settings = get_table('select * from system_settings', dictionary=False)[0]
        fn9_cas = get_table('select * from system_certificateauthority')
        fn9_certs = get_table('select * from system_certificate')

        # Migrating the certificate authorities and certificates
        for crypto_obj in sorted(fn9_cas.values(), key=lambda x: x['cert_type']) + list(fn9_certs.values()):
            cert_type = CRYPTO_TYPE[crypto_obj['cert_type']]
            if cert_type == 'CERT_CSR':
                self.add_warning(TaskWarning(
                    err.code,
                    'Cannot migrate CSR: {0}. Migrating CSRs is not supported'.format(crypto_obj['cert_name'])
                ))
                continue

            # Now since we are going to import these certs to fn10 let us mark them as
            # CERT/CA EXISTING and nothing else, as only those will work and make sense
            # in this migration scenario
            cert_type = 'CERT_EXISTING' if cert_type.startswith('CERT') else 'CA_EXISTING'
            try:
                signed_by_ca = fn9_cas.get(crypto_obj['cert_signedby_id'])
                self.run_subtask_sync(
                    'crypto.certificate.import',
                    {
                        'type': cert_type,
                        'name': crypto_obj['cert_name'],
                        'certificate': crypto_obj['cert_certificate'],
                        'privatekey': crypto_obj['cert_privatekey'],
                        'signing_ca_name': signed_by_ca['cert_name'] if signed_by_ca else None
                    },
                    validate=True
                )
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Could not migrate CA/Cert: {0} due to error: {1}'.format(crypto_obj['cert_name'], err)
                ))

        # Migrating system general settings over to 10
        try:
            system_general_config = {
                'language': fn9_sys_settings['stg_language'],
                'timezone': fn9_sys_settings['stg_timezone'],
                'syslog_server': fn9_sys_settings['stg_syslogserver'] or None
            }
            if fn9_sys_settings['stg_kbdmap']:
                system_general_config.update({'console_keymap': fn9_sys_settings['stg_kbdmap']})

            self.run_subtask_sync('system.general.update', system_general_config, validate=True)
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code,
                'Could not migrate system general settings due to error: {0}'.format(err)
            ))

        try:
            fn10_certs_and_cas = list(self.dispatcher.call_sync('crypto.certificate.query'))
            webui_cert9 = fn9_certs.get(fn9_sys_settings['stg_guicertificate_id'], {})
            webgui_cert = q.query(
                fn10_certs_and_cas,
                ('name', '=', webui_cert9.get('cert_name')),
                single=True
            )
            self.run_subtask_sync(
                'system.ui.update',
                {
                    'webui_protocol': PROTOCOL_CHOICES[fn9_sys_settings['stg_guiprotocol']],
                    'webui_listen': [
                        fn9_sys_settings['stg_guiaddress'],
                        fn9_sys_settings['stg_guiv6address']
                    ],
                    'webui_http_redirect_https': bool(fn9_sys_settings['stg_guihttpsredirect']),
                    'webui_http_port': fn9_sys_settings['stg_guiport'],
                    'webui_https_certificate': webgui_cert['id'] if webgui_cert else None,
                    'webui_https_port': fn9_sys_settings['stg_guihttpsport']
                },
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate system ui settings due to error: {0}'.format(err)
            ))

        # Migrating system advanced settings over to 10
        fn9_adv_settings = get_table('select * from system_advanced', dictionary=False)[0]
        try:
            # Note not migrating the `powerd` property since it is automagically managed by fn10
            # also not carrying forward periodic_notify_user as there is no use for it in 10
            self.run_subtask_sync(
                'system.advanced.update',
                {
                    'console_cli': bool(fn9_adv_settings['adv_consolemenu']),
                    'console_screensaver': bool(fn9_adv_settings['adv_consolescreensaver']),
                    'serial_console': bool(fn9_adv_settings['adv_serialconsole']),
                    'serial_port': fn9_adv_settings['adv_serialport'],
                    'serial_speed': int(fn9_adv_settings['adv_serialspeed']),
                    'swapondrive': fn9_adv_settings['adv_swapondrive'],
                    'debugkernel': bool(fn9_adv_settings['adv_debugkernel']),
                    'uploadcrash': bool(fn9_adv_settings['adv_uploadcrash']),
                    'motd': fn9_adv_settings['adv_motd'],
                    'boot_scrub_internal': fn9_adv_settings['adv_boot_scrub'],
                    'graphite_servers': [fn9_adv_settings['adv_graphite']] if fn9_adv_settings['adv_graphite'] else []
                },
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code,
                'Could not migrate system advanced settings due to error: {0}'.format(err)
            ))

        # Migrating email settings
        fn9_email = get_table('select * from system_email', dictionary=False)[0]
        fn9_root_user = get_table('select * from account_bsdusers').pop(1)
        try:
            self.run_subtask_sync(
                'alert.emitter.update',
                self.dispatcher.call_sync(
                    'alert.emitter.query', [("name", "=", "email")], {'single': True}
                )['id'],
                {
                    'config': {
                        'from_address': fn9_email['em_fromemail'],
                        'to': [fn9_root_user['bsdusr_email']] if fn9_root_user['bsdusr_email'] else [],
                        'server': fn9_email['em_outgoingserver'],
                        'port': fn9_email['em_port'],
                        'auth': bool(fn9_email['em_smtp']),
                        'encryption': fn9_email['em_security'].upper(),
                        'user': fn9_email['em_user'] or None,
                        'password': {
                            '$password': self._notifier.pwenc_decrypt(fn9_email['em_pass'])
                        } if fn9_email['em_pass'] else None
                    }
                },
                validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, 'Could not migrate email settings due to error: {0}'.format(err)
            ))

        # Migrating ntpservers' settings
        fn9_ntp_servers = get_table('select * from system_ntpserver')
        fn10_ntp_servers = list(self.dispatcher.call_sync('ntp_server.query'))

        for fn9_ntp in fn9_ntp_servers.values():
            try:
                fn10_ntp = q.query(
                    fn10_ntp_servers, ("address", "=", fn9_ntp['ntp_address']), single=True
                )
                ntp_task_args = [
                    'ntp_server.update' if fn10_ntp else 'ntp_server.create',
                    fn10_ntp['id'] if fn10_ntp else None,
                    {
                        'address': fn9_ntp['ntp_address'],
                        'burst': bool(fn9_ntp['ntp_burst']),
                        'iburst': bool(fn9_ntp['ntp_iburst']),
                        'prefer': bool(fn9_ntp['ntp_prefer']),
                        'minpoll': fn9_ntp['ntp_minpoll'],
                        'maxpoll': fn9_ntp['ntp_maxpoll'],
                        'pool': fn10_ntp['pool'] if fn10_ntp else True,
                    },
                    True
                ]
                self.run_subtask_sync(*list(filter(None, ntp_task_args)), validate=True)
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code, 'Could not migrate npt_server: {0} due to error: {1}'.format(
                        fn9_ntp['ntp_address'], err
                    )
                ))

        # Migrating system tunables
        fn9_tunables = get_table('select * from system_tunable')
        for fn9_tunable in fn9_tunables.values():
            try:
                if fn9_tunable['tun_type'].upper() == 'RC':
                    raise RpcException(errno.EINVAL, 'RC tunables are no longer supported')
                self.run_subtask_sync(
                    'tunable.create',
                    {
                        'type': fn9_tunable['tun_type'].upper(),
                        'var': fn9_tunable['tun_var'],
                        'value': fn9_tunable['tun_value'],
                        'comment': fn9_tunable['tun_comment'],
                        'enabled': bool(fn9_tunable['tun_enabled']),
                    },
                    validate=True
                )
            except RpcException as err:
                self.add_warning(TaskWarning(
                    err.code,
                    'Could not migrate {0} tunable: {1} due to error: {2}'.format(
                        fn9_tunable['tun_type'].upper(), fn9_tunable['tun_var'], err
                    )
                ))

        # Migrate system dataset (only pool setting is migrated though)
        fn9_sysdataset = get_table('select * from system_systemdataset', dictionary=False)[0]
        try:
            self.run_subtask_sync(
                'system_dataset.migrate', fn9_sysdataset['sys_pool'], validate=True
            )
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code,
                'Failed to migrate system dataset to pool: {0} due to error'.format(
                    fn9_sysdataset['sys_pool'], err
                )
            ))


@description("Calendar task settings migration task")
class CalendarMigrateTask(Task):
    def __init__(self, dispatcher):
        super(CalendarMigrateTask, self).__init__(dispatcher)
        self._notifier = notifier()

    @classmethod
    def early_describe(cls):
        return "Migration of 9.x calendar tasks to 10"

    def describe(self):
        return TaskDescription("Migration of 9.x calendar tasks to 10")

    def run(self):
        # Lets get the fn9.x tasks data
        fn9_smart_tasks = get_table('select * from tasks_smarttest')
        fn9_smart_disk_map = get_table('select * from tasks_smarttest_smarttest_disks')
        fn9_rsync_tasks = get_table('select * from tasks_rsync')
        fn9_shutdown_tasks = get_table('select * from tasks_initshutdown')
        fn9_cron_tasks = get_table('select * from tasks_cronjob')
        fn9_storage_tasks = get_table('select * from storage_task')
        fn9_scrub_tasks = get_table('select * from storage_scrub')

        # # migrating SMART TEST tasks
        # for fn9_smart_task in fn9_smart_tasks.values():
        #     try:
        #         self.dispatcher.run_subtask_sync(
        #             'calendar_task.create',
        #             {
        #                 'name': ,
        #                 'task':
        #             }
        #         )
        #     except RpcException as err:
        #         self.add_warning(TaskWarning(
        #             err.code,
        #             'Failed to migrate calendar task: {0} due to error: {1}'.format(, err)
        #         ))


@description("Directory services migration task")
class DirectoryServicesMigrateTask(Task):
    def __init__(self, dispatcher):
        super(DirectoryServicesMigrateTask, self).__init__(dispatcher)
        self._notifier = notifier()

    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x Directory Services settings (AD, LDAP, NIS)"

    def describe(self):
        return TaskDescription(
            "Migration of FreeNAS 9.x Directory Services settings (AD, LDAP, NIS)"
        )

    def run(self):
        # get all directory services settings from fn9 database
        fn9_ad = get_table('select * from directoryservice_activedirectory', dictionary=False)[0]
        fn9_ad_idmap = get_table('select * from directoryservice_idmap_ad', dictionary=False)[0]
        fn9_rid_idmap = get_table('select * from directoryservice_idmap_rid')


@description("FreeNAS 9 passphrased volumes unlock and import task")
@accepts(h.array(h.object(properties={'name': str, 'passphrase': Password}, additionalProperties=False)))
class PassEncVolumeImportTask(StorageMigrateTask):
    @classmethod
    def early_describe(cls):
        return "Unlock and import of FreeNAS 9.x passphrase encrypted volumes"

    def describe(self, volimport):
        return TaskDescription(
            "Unlocking and importing volumes: {vols}",
            vols=', '.join(filter(None, (v.get('name') for v in volimport)))
        )

    def verify(self, volimport):
        return ['system']

    def run(self, volimport):
        self.fn10_disks = list(self.dispatcher.call_sync('disk.query'))
        fn9_enc_disks = get_table('select * from storage_encrypteddisk')
        fn9_passenc_vols = {
            v['vol_name']: extend(
                v,
                {'enc_disks': [enc for enc in fn9_enc_disks.values() if enc['encrypted_volume_id'] == v['id']]}
            ) for v in get_table('select * from storage_volume').values() if v['vol_encrypt'] > 1
        }
        for vol in volimport:
            fn9_volume = fn9_passenc_vols.get(vol['name'])
            if fn9_volume:
                try:
                    with open(f"/data/geli/{fn9_volume['vol_encryptkey']}.key", "rb") as key_file:
                        key_contents = base64.b64encode(key_file.read()).decode('utf-8')

                    encrypted_disks = []
                    for ed in fn9_volume['enc_disks']:
                        enc_disk = self.identifier_to_device(ed['encrypted_disk_id'])
                        if enc_disk:
                            encrypted_disks.append(os.path.join('/dev', enc_disk))

                    self.run_subtask_sync(
                        'volume.import',
                        fn9_volume['vol_guid'],
                        fn9_volume['vol_name'],
                        {},
                        {
                            'key': key_contents,
                            'disks': encrypted_disks
                        },
                        vol['passphrase'],
                        validate=True
                    )
                except (OSError, RpcException) as err:
                    raise TaskException(
                        getattr(err, 'code', errno.EINVAL),
                        f"Import of volume named: {fn9_volume['vol_name']} guid: {fn9_volume['vol_guid']} failed due to err: {err}"
                    )
            else:
                raise TaskException(
                    errno.ENXIO,
                    f"Volume: {vol['name']} not in FreeNAS 9.x passphrase encrypted volumes list"
                )


@description("Master top level migration task for 9.x to 10.x")
@accepts(h.one_of(bool, None), h.one_of(bool, None))
class MasterMigrateTask(ProgressTask):
    def __init__(self, dispatcher, second_run=False, ignore_encrypted_volumes=False):
        super(MasterMigrateTask, self).__init__(dispatcher)
        self.status = 'STARTED'
        self.apps_migrated = []
        self.progress_tracker = 0

        # migration app to (task, args, status message) mappings
        self.critical_migrations = OrderedDict([
            (
                'root user',
                {
                    'task_name': 'migration.accountsmigrate',
                    'args': ['root'],
                    'msg': 'Migrating root user settings'
                }
            ),
            (
                'network',
                {
                    'task_name': 'migration.networkmigrate',
                    'args': [],
                    'msg': 'Migrating network app'
                }
            ),
            (
                'storage',
                {
                    'task_name': 'migration.storagemigrate',
                    'args': [],
                    'msg': 'Migrating storage app: disks and volumes'
                }
            ),
            (
                'system',
                {
                    'task_name': 'migration.systemmigrate',
                    'args': [],
                    'msg': 'Migrating system app'
                }
            )
        ])

        self.non_critical_migrations = OrderedDict([
            (
                'accounts',
                {
                    'task_name': 'migration.accountsmigrate',
                    'args': ['non-root'],
                    'msg': 'Migrating accounts app: users and groups'
                }
            ),
            (
                'services',
                {
                    'task_name': 'migration.servicemigrate',
                    'args': [],
                    'msg': 'Migrating services app'
                }
            ),
            (
                'shares',
                {
                    'task_name': 'migration.sharemigrate',
                    'args': [],
                    'msg': 'Migrating shares app'
                }
            ),
            # (
            #     'calendar',
            #     {
            #         'task_name': 'migration.calendarmigrate',
            #         'args': [],
            #         'msg': 'Migrating calendar tasks'
            #     }
            # ),
            # (
            #     'directoryservices',
            #     {
            #         'task_name': 'migration.directoryservicesmigrate',
            #         'args': [],
            #         'msg': 'Migrating directory services settings'
            #     }
            # )
        ])

    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x settings to 10"

    def describe(self, second_run=False, ignore_encrypted_volumes=False):
        desc = "Migration of FreeNAS 9.x settings to 10"
        if second_run:
            if ignore_encrypted_volumes:
                desc = "Resuming FreeNAS 9.x to 10 settings migration (ignoring passphrase encrypted volumes)"
            else:
                desc = "Resuming FreeNAS 9.x to 10 settings migration post unlocking of passphrase encrypted volumes"
        return TaskDescription(desc)

    def migration_progess(self, progress, message):
        self.set_progress(progress, message)
        migration_status = {
            'plugin': 'MigrationPlugin',
            'apps_migrated': self.apps_migrated,
            'migration_progress': progress,
            'status': self.status
        }
        self.dispatcher.dispatch_event('migration.status', migration_status)
        try:
            push_status('MigrationPlugin: {0}'.format(message), extra=migration_status)
        except:
            # don't fail if you cannot set status d'oh
            pass

    def migration_task_routine(self, app, task_dict):
        try:
            self.progress_tracker += 10
            self.migration_progess(self.progress_tracker, task_dict.get('msg', f'Migrating {app} app'))
            self.run_subtask_sync(task_dict['task_name'], *task_dict.get('args', []), validate=True)
            self.apps_migrated.append(app)
        except RpcException as err:
            self.add_warning(TaskWarning(
                err.code, f'Failed to successfully migrate: {app} due to {err}'
            ))

    def verify(self, second_run=False, ignore_encrypted_volumes=False):
        return ['root']

    def run(self, second_run=False, ignore_encrypted_volumes=False):
        try:
            self.migration_progess(0, 'Starting migration from 9.x database to 10.x')

            if not second_run:
                # bring the 9.x database up to date with the latest 9.x version
                # doing this via a subprocess call since otherwise there are much import
                # issues which I tried hunting down but could not finally resolve
                try:
                    out, err = system('/usr/local/sbin/migrate93', '-f', FREENAS93_DATABASE_PATH)
                except SubprocessException as e:
                    logger.error('Traceback of 9.x database migration', exc_info=True)
                    raise TaskException(
                        'Error whilst trying upgrade 9.x database to latest 9.x schema: {0}'.format(e)
                    )
                logger.debug(
                    'Result of running 9.x was as follows: stdout: {0}, stderr: {1}'.format(out, err)
                )

            self.status = 'RUNNING'

            if not second_run:
                for app, task_tuple in self.critical_migrations.items():
                    self.migration_task_routine(app, task_tuple)

            if not ignore_encrypted_volumes:
                # check if the passphrase encrypted volumes are imported into the system
                fn10_vols = list(self.dispatcher.call_sync('volume.query'))
                vols_left_to_import = []

                for fn9_volume in get_table('select * from storage_volume').values():
                    if (
                        fn9_volume['vol_encrypt'] > 1 and
                        q.query(fn10_vols, ('guid', '=', fn9_volume['vol_guid']), single=True) is None
                    ):
                        vols_left_to_import.append(fn9_volume['vol_name'])

                if vols_left_to_import:
                    self.status = 'STOPPED'
                    self.migration_progess(
                        self.progress_tracker,
                        'Migration of FreeNAS 9.x database deferred pending manual import of passphrase encrypted volumes'
                    )
                    self.dispatcher.call_sync(
                        'alert.emit',
                        {
                            'clazz': 'MigrationStalled',
                            'title': 'FreeNAS 9.x to 10 migration stopped',
                            'description': f"Please import passphrase encrypted volumes: {', '.join(vols_left_to_import)} and resume migrations from CLI",
                            'target': ', '.join(vols_left_to_import)
                        }
                    )
                    self.add_warning(TaskWarning(
                        errno.ENXIO,
                        "Migration stopped: pending import of passphrase encrypted volumes: {0}.".format(
                            ', '.join(vols_left_to_import)
                        )
                    ))
                    return

            # Putting this here explicity so that when this task is run with second_run = True
            self.progress_tracker = len(self.critical_migrations) * 10
            # Here put the check in for passphrase based encrypted volumes and decided whether
            # we should succeed or not
            for app, task_tuple in self.non_critical_migrations.items():
                self.migration_task_routine(app, task_tuple)

            # If we reached till here migration must have succeeded
            # so lets rename the databse
            os.rename(FREENAS93_DATABASE_PATH, "{0}.done".format(FREENAS93_DATABASE_PATH))

            self.status = 'FINISHED'
            self.migration_progess(100, 'Migration of FreeNAS 9.x database config and settings done')

            self.dispatcher.call_sync(
                'alert.emit',
                {
                    'clazz': 'MigrationDone',
                    'title': 'FreeNAS 9.x to 10 migration completed',
                    'description': 'Successfully migrated FreeNAS 9.x settings and configurations'
                }
            )
        except Exception as err:
            # I know a broad catch-all is hacky but I need this for sending the serviced event
            # which will release the splash screen
            self.status = 'FAILED'
            self.migration_progess(
                self.progress_tracker, f'Master migration task failed due to {err}'
            )
            self.dispatcher.call_sync(
                'alert.emit',
                {
                    'clazz': 'MigrationFailed',
                    'title': 'FreeNAS 9.x to 10 migration failed!',
                    'description': f'Master migration task failed due to {err}'
                }
            )
            raise TaskException(errno.EINVAL, f'Master migration task failed due to {err}')


def _init(dispatcher, plugin):

    def start_migration(args):
        logger.debug('Starting migration from 9.x database to 10.x')
        dispatcher.call_task_sync('migration.mastermigrate')

    plugin.register_schema_definition('migration-status', {
        'type': 'object',
        'properties': {
            'plugin': {'type': 'string', 'enum': ['MigrationPlugin']},
            'apps_migrated': {
                'type': 'array',
                'items': {'type': 'string'},
            },
            'migration_progress': {'type': 'integer'},
            'status': {
                'type': 'string',
                'enum': ['NOT_NEEDED', 'STARTED', 'RUNNING', 'FINISHED', 'STOPPED', 'FAILED']}
        }
    })

    plugin.register_task_handler('migration.mastermigrate', MasterMigrateTask)
    plugin.register_task_handler('migration.accountsmigrate', AccountsMigrateTask)
    plugin.register_task_handler('migration.networkmigrate', NetworkMigrateTask)
    plugin.register_task_handler('migration.storagemigrate', StorageMigrateTask)
    plugin.register_task_handler('migration.sharemigrate', ShareMigrateTask)
    plugin.register_task_handler('migration.servicemigrate', ServiceMigrateTask)
    plugin.register_task_handler('migration.systemmigrate', SystemMigrateTask)
    plugin.register_task_handler('migration.calendarmigrate', CalendarMigrateTask)
    plugin.register_task_handler('migration.directoryservicesmigrate', DirectoryServicesMigrateTask)
    plugin.register_task_handler('migration.import_encvolume', PassEncVolumeImportTask)

    plugin.register_event_type('migration.status')

    if os.path.exists(FREENAS93_DATABASE_PATH):
        # Ensure that networkd and Migration plugin do not both try to race to configure
        # network interfaces by setting `autoconfigure` flag to False
        dispatcher.configstore.set('network.autoconfigure', False)
        plugin.register_event_handler('service.ready', start_migration)
    else:
        migration_status = {
            'plugin': 'MigrationPlugin',
            'apps_migrated': [],
            'status': 'NOT_NEEDED'
        }
        dispatcher.dispatch_event('migration.status', migration_status)
        push_status('MigrationPlugin: Migration not needed', extra=migration_status)
