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
import uuid
import krb5
import ldap3
import ldap3.utils.conv
import smbconf
import wbclient
import logging
import subprocess
import errno
import time
import contextlib
from typing import Optional
from threading import Thread, Condition
from datetime import datetime
from plugin import DirectoryServicePlugin, DirectoryState, params, status
from utils import domain_to_dn, join_dn, obtain_or_renew_ticket, have_ticket, get_srv_records, get_a_records
from utils import split_sid, LdapQueryBuilder
from sid import SID
from freenas.dispatcher import Password
from freenas.dispatcher.model import BaseStruct, BaseEnum, BaseVariantType, types
from freenas.utils import normalize, first_or_default
from freenas.utils.query import get


AD_REALM_ID = uuid.UUID('01a35b82-0168-11e6-88d6-0cc47a3511b4')
WINBINDD_PIDFILE = '/var/run/samba4/winbindd.pid'
WINBINDD_KEEPALIVE = 60
AD_LDAP_ATTRIBUTE_MAPPING = {
    'id': 'objectGUID',
    'sd': 'objectSid',
    'username': 'sAMAccountName',
    'full_name': 'name',
    'builtin': True,
    'uid': None,
    'gid': None
}

logger = logging.getLogger(__name__)


class WinbindIdmapConfig(BaseVariantType):
    pass


class WinbindIdmapRidConfig(BaseStruct):
    __variant_of__ = WinbindIdmapConfig
    base_rid: int
    range_start: int
    range_end: int


class WinbindIdmapUnixSchema(BaseEnum):
    RFC2307 = 'RFC2307'
    SFU = 'SFU'
    SFU20 = 'SFU20'


class WinbindIdmapUnixConfig(BaseStruct):
    __variant_of__ = WinbindIdmapConfig
    schema: WinbindIdmapUnixSchema


class WinbindIdmapAppleConfig(BaseStruct):
    __variant_of__ = WinbindIdmapConfig


class WinbindSaslWrapping(BaseEnum):
    PLAIN = 'PLAIN'
    SIGN = 'SIGN'
    SEAL = 'SEAL'


class WinbindIdmapType(BaseEnum):
    RID = 'RID'
    UNIX = 'UNIX'
    APPLE = 'APPLE'


class WinbindDirectoryParams(BaseStruct):
    __variant_of__ = types.DirectoryParams
    realm: str
    username: Optional[str]
    password: Optional[Password]
    krb_principal: Optional[str]
    site_name: Optional[str]
    dc_address: Optional[str]
    gcs_address: Optional[str]
    allow_dns_updates: bool
    sasl_wrapping: WinbindSaslWrapping
    idmap_type: WinbindIdmapType
    idmap: WinbindIdmapConfig


class WinbindDirectoryStatus(BaseStruct):
    __variant_of__ = types.DirectoryStatus
    joined: bool
    domain_controller: str
    server_time: datetime


def yesno(val):
    return 'yes' if val else 'no'


class RIDMapper(object):
    def __init__(self, context, params):
        self.context = context
        self.base_rid = params['base_rid']
        self.start = params['range_start']
        self.end = params['range_end']

    def get_uid(self, user):
        base, rid = split_sid(user['objectSid'])
        return int(rid) - self.base_rid + self.start

    def get_gid(self, group):
        base, rid = split_sid(group['objectSid'])
        return int(rid) - self.base_rid + self.start

    def get_by_uid(self, uid):
        rid = uid - self.start + self.base_rid
        sid = f'{self.context.domain_sid}-{rid}'
        return self.context.getsid(sid)

    def get_by_gid(self, gid):
        rid = gid - self.start + self.base_rid
        sid = f'{self.context.domain_sid}-{rid}'
        return self.context.getsid(sid)


class UnixMapper(object):
    def __init__(self, context, params):
        self.context = context

    def get_uid(self, user):
        return user.get('uidNumber')

    def get_gid(self, group):
        return group.get('gidNumber')

    def get_by_uid(self, uid):
        return self.context.convert_user(self.context.search_one(self.context.base_dn, f'(uidNumber={uid})'))

    def get_by_gid(self, gid):
        return self.context.convert_group(self.context.search_one(self.context.base_dn, f'(gidNumber={gid})'))


class AppleMapper(object):
    def __init__(self, context, params):
        self.context = context

    def get_uid(self, user):
        pass

    def get_gid(self, group):
        pass


MAPPERS = {
    'RID': RIDMapper,
    'UNIX': UnixMapper,
    'APPLE': AppleMapper
}


@params(WinbindDirectoryParams)
@status(WinbindDirectoryStatus)
class WinbindPlugin(DirectoryServicePlugin):
    def __init__(self, context):
        self.context = context
        self.uid_min = 90000001
        self.uid_max = 100000000
        self.dc = None
        self.enabled = False
        self.domain_info = None
        self.domain_name = None
        self.parameters = None
        self.directory = None
        self.ldap_servers = None
        self.ldap = None
        self.domain_sid = None
        self.domain_admins_sid = None
        self.domain_users_guid = None
        self.wheel_group = None
        self.mapper = None
        self.workgroup = ''
        self.cv = Condition()
        self.bind_thread = Thread(target=self.bind, daemon=True)
        self.bind_thread.start()
        os.environ['LOGNAME'] = 'root'

        # Remove winbind cache files
        with contextlib.suppress(FileNotFoundError):
            os.remove('/var/db/samba4/winbindd_cache.tdb')

        with contextlib.suppress(FileNotFoundError):
            os.remove('/var/db/samba4/winbindd_cache.tdb.bak')

        with contextlib.suppress(FileNotFoundError):
            os.remove('/var/db/samba4/winbindd_cache.tdb.old')

    @property
    def realm(self):
        return self.parameters['realm']

    @property
    def base_dn(self):
        return domain_to_dn(self.realm)

    @property
    def wbc(self):
        return wbclient.Context()

    @property
    def principal(self):
        return '{0}@{1}'.format(self.parameters['username'], self.parameters['realm'].upper())

    @property
    def domain_users_sid(self):
        return f'{self.domain_info.sid}-513'

    @property
    def ldap_addresses(self):
        records = get_srv_records('ldap', 'tcp', self.parameters['realm'])
        return [str(i) for i in records]

    @staticmethod
    def normalize_parameters(parameters):
        return normalize(parameters, {
            '%type': 'WinbindDirectoryParams',
            'realm': '',
            'username': 'Administrator',
            'password': None,
            'krb_principal': None,
            'site_name': None,
            'dc_address': None,
            'gcs_address': None,
            'allow_dns_updates': True,
            'sasl_wrapping': 'PLAIN',
            'idmap_type': 'RID',
            'idmap': {
                '%type': 'WinbindIdmapRidConfig',
                'base_rid': 0,
                'range_start': 20000,
                'range_end': 10000000
            }
        })

    def is_joined(self, full=False):
        if full:
            # Check if we have ticket
            if not have_ticket(self.principal):
                logger.debug('Ticket not found or expired')
                return False

            # Check if we can fetch domain SID
            try:
                subprocess.check_output(['/usr/local/bin/net', 'getdomainsid'])
            except subprocess.CalledProcessError:
                logger.debug('Cannot fetch domain SID')
                return False

        # Check if winbind is running
        if self.wbc.interface is None:
            logger.debug('Winbind client interface not available')
            return False

        return True

    def __renew_ticket(self):
        obtain_or_renew_ticket(self.principal, self.parameters['password'])

    def search(self, search_base, search_filter, attributes=None):
        if self.ldap.closed:
            self.ldap_bind()

        return filter(
            lambda i: i['type'] != 'searchResRef',
            self.ldap.extend.standard.paged_search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes or ldap3.ALL_ATTRIBUTES,
                paged_size=16,
                generator=True
            )
        )

    def search_dn(self, dn, attributes=None):
        if self.ldap.closed:
            self.ldap_bind()

        return first_or_default(None, self.ldap.extend.standard.paged_search(
            search_base=dn,
            search_filter='(objectclass=*)',
            search_scope=ldap3.BASE,
            attributes=attributes or ldap3.ALL_ATTRIBUTES,
            paged_size=1,
            generator=False
        ))

    def search_one(self, *args, **kwargs):
        return first_or_default(None, self.search(*args, **kwargs))

    def get_netbios_domain_name(self):
        partition = self.search_one(f'cn=Partitions,cn=Configuration,{self.base_dn}', '(nETBIOSName=*)')
        return partition['attributes']['nETBIOSName']

    def connect(self):
        logger.debug('Initializing LDAP connection')
        logger.debug('LDAP server addresses: {0}'.format(', '.join(self.ldap_addresses)))
        ldap_addresses = self.ldap_addresses

        if self.parameters.get('dc_address'):
            logger.debug('Using manually configured DC address')
            ldap_addresses = [self.parameters.get('dc_address')]

        self.ldap_servers = [ldap3.Server(i) for i in ldap_addresses]
        self.ldap = ldap3.Connection(
            self.ldap_servers,
            client_strategy='ASYNC',
            authentication=ldap3.SASL,
            sasl_mechanism='GSSAPI',
            sasl_credentials=None
        )

        self.ldap_bind()
        logger.debug('LDAP bound')

    def ldap_bind(self):
        if not self.ldap.bind():
            # try TLS now
            self.ldap.start_tls()
            if not self.ldap.bind():
                raise RuntimeError("Failed to bind")

    def bind(self):
        logger.debug('Bind thread: starting')
        while True:
            with self.cv:
                notify = self.cv.wait(60)

                if notify:
                    if self.is_joined() and self.enabled:
                        self.directory.put_state(DirectoryState.EXITING)
                        self.leave()

                if self.enabled:
                    try:
                        obtain_or_renew_ticket(self.principal, self.parameters['password'])
                    except krb5.KrbException as err:
                        self.directory.put_status(errno.ENXIO, '{0} <{1}>'.format(str(err), type(err).__name__))
                        self.directory.put_state(DirectoryState.FAILURE)
                        continue

                    if not self.is_joined(True):
                        # Try to rejoin
                        logger.debug('Keepalive thread: rejoining')
                        self.directory.put_state(DirectoryState.JOINING)
                        if not self.join():
                            continue
                    else:
                        self.domain_info = self.wbc.get_domain_info(self.realm)
                        self.domain_name = self.wbc.interface.netbios_domain

                    if self.directory.state != DirectoryState.BOUND:
                        try:
                            # Get the domain object
                            domain = self.search_dn(self.base_dn)
                            if not domain:
                                raise RuntimeError('Failed to fetch domain LDAP object, incorrect realm?')

                            self.domain_sid = domain['attributes']['objectSid']
                            self.domain_admins_sid = f'{self.domain_sid}-512'
                            logger.info('Domain SID: {0}'.format(self.domain_sid))

                            # Figure out group DN and prefetch "Domain Users" GUID
                            dsid = SID('{0}-{1}'.format(self.domain_sid, 513))
                            du = self.search_one(self.base_dn, '(objectSid={0})'.format(dsid.ldap()))
                            if not du:
                                raise RuntimeError('Failed to fetch Domain Users')

                            self.domain_users_guid = uuid.UUID(du['attributes']['objectGUID'])
                            logger.debug('Domain Users GUID is {0}'.format(self.domain_users_guid))
                        except BaseException as err:
                            logger.debug('Failure details', exc_info=True)
                            self.directory.put_status(errno.ENXIO, '{0} <{1}>'.format(str(err), type(err).__name__))
                            self.directory.put_state(DirectoryState.FAILURE)
                        else:
                            self.directory.put_state(DirectoryState.BOUND)
                else:
                    if self.directory.state != DirectoryState.DISABLED:
                        self.leave()
                        self.directory.put_state(DirectoryState.DISABLED)

    def configure_smb(self, enable):
        workgroup = self.workgroup
        cfg = smbconf.SambaConfig('registry')
        params = {
            'server role': 'member server',
            'local master': 'no',
            'domain master': 'no',
            'preferred master': 'no',
            'domain logons': 'no',
            'workgroup': workgroup,
            'realm': self.parameters['realm'],
            'security': 'ads',
            'winbind cache time': str(self.context.cache_ttl),
            'winbind offline logon': 'yes',
            'winbind enum users': 'no',
            'winbind enum groups': 'no',
            'winbind nested groups': 'yes',
            'winbind use default domain': 'no',
            'winbind refresh tickets': 'no',
            'client use spnego': 'yes',
            'allow trusted domains': 'no',
            'client ldap sasl wrapping': self.parameters['sasl_wrapping'].lower(),
            'template shell': '/bin/sh',
            'template homedir': '/home/%U'
        }

        if enable:
            for k, v in params.items():
                logger.debug('Setting samba parameter "{0}" to "{1}"'.format(k, v))
                cfg[k] = v
        else:
            for k in params:
                del cfg[k]

            params = {
                'server role': 'auto',
                'workgroup': self.context.configstore.get('service.smb.workgroup'),
                'local master': yesno(self.context.configstore.get('service.smb.local_master'))
            }

            for k, v in params.items():
                logger.debug('Setting samba parameter "{0}" to "{1}"'.format(k, v))
                cfg[k] = v

        self.context.client.call_sync('service.restart', 'smb')

    def get_directory_info(self):
        return {
            'domain_name': self.domain_name,
            'domain_controller': self.dc
        }

    def get_domain_sid(self):
        return self.domain_sid

    def convert_user(self, entry):
        if not entry:
            return

        dn = entry['dn']
        entry = dict(entry['attributes'])
        if 'user' not in get(entry, 'objectClass'):
            # not a user
            return

        if 'computer' in get(entry, 'objectClass'):
            # not a user
            return

        username = get(entry, 'sAMAccountName')
        usersid = get(entry, 'objectSid')
        groups = []
        uid = self.mapper.get_uid(entry)

        if uid is None:
            return

        if get(entry, 'memberOf'):
            builder = LdapQueryBuilder()
            qstr = builder.build_query([
                ('member', '=', dn),
                ('objectClass', '=', 'group')
            ])

            for r in self.search(self.base_dn, qstr, attributes=['objectGUID', 'objectSid']):
                r = dict(r['attributes'])
                guid = uuid.UUID(get(r, 'objectGUID'))
                groups.append(str(guid))

                # Append wheel group to users being in Domain Admins group
                if r['objectSid'] == self.domain_admins_sid and self.wheel_group:
                    groups.append(self.wheel_group['id'])

        return {
            'id': str(uuid.UUID(get(entry, 'objectGUID'))),
            'sid': str(usersid),
            'uid': uid,
            'builtin': False,
            'username': username,
            'aliases': [f'{self.workgroup}\\{username}'],
            'full_name': get(entry, 'name'),
            'email': None,
            'locked': False,
            'sudo': False,
            'password_disabled': False,
            'group': str(self.domain_users_guid),
            'groups': groups,
            'shell': '/bin/sh',
            'home': self.context.get_home_directory(self.directory, username)
        }

    def convert_group(self, entry):
        if not entry:
            return

        entry = dict(entry['attributes'])
        if 'group' not in get(entry, 'objectClass'):
            # not a group
            return

        groupname = get(entry, 'sAMAccountName')
        groupsid = get(entry, 'objectSid')
        parents = []
        gid = self.mapper.get_gid(entry)

        if gid is None:
            return

        if get(entry, 'memberOf'):
            builder = LdapQueryBuilder()
            qstr = builder.build_query([
                ('distinguishedName', 'in', get(entry, 'memberOf'))
            ])

            for r in self.search(self.base_dn, qstr):
                r = dict(r['attributes'])
                guid = uuid.UUID(get(r, 'objectGUID'))
                parents.append(str(guid))

        return {
            'id': str(uuid.UUID(get(entry, 'objectGUID'))),
            'sid': str(groupsid),
            'gid': gid,
            'builtin': False,
            'name': groupname,
            'aliases': [f'{self.workgroup}\\{groupname}'],
            'parents': parents,
            'sudo': False
        }

    def getpwent(self, filter=None, params=None):
        logger.debug('getpwent(filter={0}, params={1})'.format(filter, params))
        if not self.is_joined():
            logger.debug('getpwent: not joined')
            return []

        query = LdapQueryBuilder(AD_LDAP_ATTRIBUTE_MAPPING)
        qfilter = [['objectClass', '=', 'person']] + (filter or [])
        if self.parameters['idmap_type'] == 'UNIX':
            qfilter.append(['uidNumber', '~', '*'])

        qstr = query.build_query(qfilter)
        logger.debug('getpwent query string: {0}'.format(qstr))
        results = self.search(self.base_dn, qstr)
        return (self.convert_user(i) for i in results)

    def getpwuid(self, uid):
        if not self.is_joined():
            logger.debug('getpwuid: not joined')
            return

        return self.mapper.get_by_uid(uid)

    def getpwuuid(self, id):
        if not self.is_joined():
            logger.debug('getpwuuid: not joined')
            return

        guid = ldap3.utils.conv.escape_bytes(uuid.UUID(id).bytes_le)
        return self.convert_user(self.search_one(self.base_dn, '(objectGUID={0})'.format(guid)))

    def getpwnam(self, name):
        if '\\' in name:
            domain, name = name.split('\\', 1)
            if domain != self.domain_name:
                return

        if not self.is_joined():
            logger.debug('getpwnam: not joined')
            return

        return self.convert_user(self.search_one(self.base_dn, '(sAMAccountName={0})'.format(name)))

    def getgrent(self, filter=None, params=None):
        logger.debug('getgrent(filter={0}, params={1})'.format(filter, params))
        if not self.is_joined():
            logger.debug('getgrent: not joined')
            return []

        query = LdapQueryBuilder(AD_LDAP_ATTRIBUTE_MAPPING)
        qfilter = [['objectClass', '=', 'group']] + (filter or [])
        if self.parameters['idmap_type'] == 'UNIX':
            qfilter.append(['gidNumber', '~', '*'])

        qstr = query.build_query(qfilter)
        logger.debug('getgrent query string: {0}'.format(qstr))
        results = self.search(self.base_dn, qstr)
        return (self.convert_group(i) for i in results)

    def getgrnam(self, name):
        if '\\' in name:
            domain, name = name.split('\\', 1)
            if domain != self.domain_name:
                return

        if not self.is_joined():
            logger.debug('getgrnam: not joined')
            return

        return self.convert_group(self.search_one(self.base_dn, f'(sAMAccountName={name})'))

    def getgruuid(self, id):
        if not self.is_joined():
            logger.debug('getgruuid: not joined')
            return

        guid = ldap3.utils.conv.escape_bytes(uuid.UUID(id).bytes_le)
        return self.convert_group(self.search_one(self.base_dn, f'(objectGUID={guid})'))

    def getgrgid(self, gid):
        if not self.is_joined():
            logger.debug('getgrgid: not joined')
            return

        return self.mapper.get_by_gid(gid)

    def getsid(self, sid):
        if not self.is_joined():
            logger.debug('getsid: not joined')
            return

        sid = SID(sid)
        usid = ldap3.utils.conv.escape_bytes(sid.binary())
        result = self.search_one(self.base_dn, f'(objectSid={usid})')
        if result:
            attributes = dict(result['attributes'])
            if 'person' in attributes['objectClass']:
                return self.convert_user(result)
            else:
                return self.convert_group(result)

    def authenticate(self, username, password):
        if '\\' in username:
            domain, username = username.split('\\', 1)
            if domain != self.domain_name:
                return False

        return self.wbc.authenticate(f'{self.domain_name}\\{username}', password)

    def configure(self, enable, directory):
        with self.cv:
            self.wheel_group = self.context.group_service.getgrnam('wheel')
            self.enabled = enable
            self.directory = directory
            self.parameters = directory.parameters
            if directory.min_uid:
                self.uid_min = directory.min_uid
                self.uid_max = directory.max_uid

            self.cv.notify_all()

        return self.realm.lower()

    def join(self):
        logger.info(f'Trying to join to {self.realm}...')

        try:
            mapper_class = MAPPERS.get(self.parameters['idmap_type'])
            if not mapper_class:
                raise RuntimeError('Invalid mapper: {self.parameters["idmap_type"]}')

            self.mapper = mapper_class(self, self.parameters['idmap'])
            logger.info(f'Selected mapper is {self.mapper}')

            # First try to reach LDAP and grab the NetBIOS domain name
            self.connect()
            self.workgroup = self.get_netbios_domain_name()
            logger.debug(f'NetBIOS domain name is {self.workgroup}')

            self.configure_smb(True)

            try:
                subprocess.check_output(['/usr/local/bin/net', 'ads', 'join', self.realm, '-k'])
            except subprocess.CalledProcessError as err:
                # Undo possibly partially successful join
                subprocess.call(['/usr/local/bin/net', 'ads', 'leave', '-k'])
                raise RuntimeError(err.output.decode('utf-8'))

            self.context.client.call_sync('serviced.job.restart', 'org.samba.winbindd')
            logger.debug('Done restarting winbind')

            # Retry few times in case samba haven't finished restarting yet
            for _ in range(5):
                try:
                    self.dc = self.wbc.ping_dc(self.realm)
                    break
                except wbclient.WinbindException as err:
                    if err.code == wbclient.WinbindErrorCode.WINBIND_NOT_AVAILABLE:
                        time.sleep(1)
                        continue

                    raise
            else:
                raise RuntimeError('Cannot contact winbindd, maximum number of retries exceeded')

            self.domain_info = self.wbc.get_domain_info(self.realm)
            self.domain_name = self.wbc.interface.netbios_domain

        except BaseException as err:
            logger.debug('Failure details', exc_info=True)
            self.directory.put_status(errno.ENXIO, str(err))
            self.directory.put_state(DirectoryState.FAILURE)
            return False

        logger.info(f'Sucessfully joined to the domain {self.realm}')
        return True

    def leave(self):
        logger.info('Leaving domain')
        subprocess.call(['/usr/local/bin/net', 'cache', 'flush'])
        subprocess.call(['/usr/local/bin/net', 'ads', 'leave', '-k'])
        self.configure_smb(False)
        self.dc = None
        self.domain_name = None
        self.domain_info = None
        self.ldap = None

    def get_kerberos_realm(self, parameters):
        ret = {
            'id': AD_REALM_ID,
            'realm': parameters['realm'].upper(),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }

        if parameters.get('dc_address'):
            ret['kdc_address'] = parameters['dc_address']

        return ret


def _init(context):
    context.register_plugin('winbind', WinbindPlugin)
