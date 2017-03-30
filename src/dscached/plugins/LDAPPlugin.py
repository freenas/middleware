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

import errno
import uuid
import ldap3
import ldap3.utils.dn
import logging
import threading
import ssl
import krb5
from datetime import datetime
from plugin import DirectoryServicePlugin, DirectoryState
from utils import LdapQueryBuilder, obtain_or_renew_ticket, join_dn, dn_to_domain, domain_to_dn, uuid2, parse_uuid2
from utils import crc32
from freenas.utils import first_or_default, normalize
from freenas.utils.query import get, contains


TICKET_RENEW_LIFE = 30 * 86400  # 30 days
logger = logging.getLogger(__name__)


class LDAPPlugin(DirectoryServicePlugin):
    def __init__(self, context):
        self.context = context
        self.directory = None
        self.enabled = False
        self.server = None
        self.conn = None
        self.parameters = None
        self.base_dn = None
        self.user_dn = None
        self.group_dn = None
        self.start_tls = False
        self.bind_lock = threading.RLock()
        self.bind_thread = threading.Thread(target=self.bind, daemon=True)
        self.cv = threading.Condition()
        self.bind_thread.start()

    @classmethod
    def normalize_parameters(cls, parameters):
        return normalize(parameters, {
            '%type': 'LdapDirectoryParams',
            'user_suffix': 'ou=users',
            'group_suffix': 'ou=groups',
            'krb_principal': None,
            'encryption': 'OFF',
            'certificate': None,
            'verify_certificate': True
        })

    def search(self, search_base, search_filter, attributes=None):
        if self.conn.closed:
            with self.bind_lock:
                self.conn.bind()

        id = self.conn.search(search_base, search_filter, attributes=attributes or ldap3.ALL_ATTRIBUTES)
        result, status = self.conn.get_response(id)
        return result

    def search_one(self, *args, **kwargs):
        return first_or_default(None, self.search(*args, **kwargs))

    def get_id(self, entry):
        checksum = crc32(dn_to_domain(self.parameters['base_dn']))

        if 'entryUUID' in entry:
            return get(entry, 'entryUUID')

        if 'uidNumber' in entry:
            return str(uuid2(checksum, int(get(entry, 'uidNumber'))))

        if 'gidNumber' in entry:
            return str(uuid2(checksum, int(get(entry, 'gidNumber'))))

        return str(uuid.uuid4())

    def get_gecos(self, entry):
        pass

    def convert_user(self, entry):
        entry = dict(entry['attributes'])
        pwd_change_time = get(entry, 'sambaPwdLastSet')
        groups = []
        group = None
        username = get(entry, 'uid.0')

        if contains(entry, 'gidNumber'):
            ret = self.search_one(
                self.group_dn,
                '(gidNumber={0})'.format(get(entry, 'gidNumber'))
            )

            if ret:
                group = dict(ret['attributes'])

        # Try to find any auxiliary groups
        for i in self.search(self.group_dn, '(memberUid={0})'.format(get(entry, 'uid'))):
            g = dict(i['attributes'])
            groups.append(self.get_id(g))

        return {
            'id': self.get_id(entry),
            'sid': get(entry, 'sambaSID'),
            'uid': int(get(entry, 'uidNumber')),
            'builtin': False,
            'username': username,
            'full_name': get(entry, 'gecos', get(entry, 'displayName')) or '<unknown>',
            'shell': get(entry, 'loginShell', '/bin/sh'),
            'home': self.context.get_home_directory(self.directory, username),
            'nthash': get(entry, 'sambaNTPassword'),
            'lmhash': get(entry, 'sambaLMPassword'),
            'password_changed_at': datetime.utcfromtimestamp(int(pwd_change_time)) if pwd_change_time else None,
            'group': self.get_id(group) if group else None,
            'groups': groups,
            'sudo': False
        }

    def convert_group(self, entry):
        entry = dict(entry['attributes'])
        return {
            'id': self.get_id(entry),
            'gid': int(get(entry, 'gidNumber')),
            'sid': get(entry, 'sambaSID'),
            'name': get(entry, 'cn.0'),
            'builtin': False,
            'sudo': False
        }

    def getpwent(self, filter=None, params=None):
        logger.debug('getpwent(filter={0}, params={0})'.format(filter, params))
        result = self.search(self.user_dn, '(objectclass=posixAccount)')
        return (self.convert_user(i) for i in result)

    def getpwnam(self, name):
        logger.debug('getpwnam(name={0})'.format(name))
        result = self.search_one(join_dn('uid={0}'.format(name), self.user_dn), '(objectclass=posixAccount)')
        return self.convert_user(result)

    def getpwuid(self, uid):
        logger.debug('getpwuid(uid={0})'.format(uid))
        result = self.search_one(self.user_dn, '(&(objectclass=posixAccount)(uidNumber={0}))'.format(uid))
        return self.convert_user(result)

    def getpwuuid(self, id):
        logger.debug('getpwuuid(uuid={0})'.format(id))

        try:
            checksum, uid = parse_uuid2(id)
            if crc32(dn_to_domain(self.base_dn)) != checksum:
                return None

            q = '(uidNumber={0})'.format(uid)
        except ValueError:
            q = '(entryUUID={0})'.format(id)

        user = self.search_one(self.user_dn, q)
        return self.convert_user(user)

    def getgrent(self, filter=None, params=None):
        logger.debug('getgrent(filter={0}, params={0})'.format(filter, params))
        result = self.search(self.group_dn, '(objectclass=posixGroup)')
        return (self.convert_group(i) for i in result)

    def getgrnam(self, name):
        logger.debug('getgrnam(name={0})'.format(name))
        result = self.search_one(join_dn('cn={0}'.format(name), self.group_dn), '(objectclass=posixGroup)')
        return self.convert_group(result)

    def getgrgid(self, gid):
        logger.debug('getgrgid(gid={0})'.format(gid))
        result = self.search_one(self.group_dn, '(&(objectclass=posixGroup)(gidNumber={0}))'.format(gid))
        return self.convert_group(result)

    def getgruuid(self, id):
        logger.debug('getgruuid(uuid={0})'.format(id))

        try:
            checksum, gid = parse_uuid2(id)
            if crc32(dn_to_domain(self.base_dn)) != checksum:
                return None

            q = '(gidNumber={0})'.format(gid)
        except ValueError:
            q = '(entryUUID={0})'.format(id)

        group = self.search_one(self.group_dn, q)
        return self.convert_group(group)

    def authenticate(self, user_name, password):
        with self.bind_lock:
            try:
                self.conn.rebind(
                    user=join_dn('uid={0}'.format(user_name), self.user_dn),
                    password=password
                )
            except ldap3.LDAPBindError:
                self.conn.bind()
                return False

            self.conn.bind()
            return True

    def configure(self, enable, directory):
        def create_server_args(params):
            validate = ssl.CERT_REQUIRED if params['verify_certificate'] else ssl.CERT_NONE

            if params['encryption'] == 'OFF':
                return {}

            if params['encryption'] == 'SSL':
                tls = ldap3.Tls(validate=validate)
                return {
                    'port': 636,
                    'use_ssl': True,
                    'tls': tls
                }

            if params['encryption'] == 'TLS':
                tls = ldap3.Tls(validate=validate)
                return {
                    'tls': tls
                }

        with self.cv:
            self.directory = directory
            self.parameters = directory.parameters
            self.enabled = enable
            self.server = ldap3.Server(self.parameters['server'], **create_server_args(self.parameters))
            self.base_dn = self.parameters['base_dn']
            self.user_dn = join_dn(self.parameters['user_suffix'], self.base_dn)
            self.group_dn = join_dn(self.parameters['group_suffix'], self.base_dn)
            self.start_tls = self.parameters['encryption'] == 'TLS'
            self.cv.notify_all()

        return dn_to_domain(directory.parameters['base_dn'])

    def bind(self):
        while True:
            with self.cv:
                notify = self.cv.wait(60)

                if self.enabled:
                    if self.parameters['krb_principal']:
                        try:
                            obtain_or_renew_ticket(
                                self.principal,
                                keytab=True,
                                renew_life=TICKET_RENEW_LIFE
                            )
                        except krb5.KrbException as err:
                            self.directory.put_status(errno.ENXIO, '{0} <{1}>'.format(str(err), type(err).__name__))
                            self.directory.put_state(DirectoryState.FAILURE)
                            continue

                    if self.directory.state == DirectoryState.BOUND and not notify:
                        continue

                    try:
                        self.directory.put_state(DirectoryState.JOINING)

                        if self.parameters['krb_principal']:
                            self.conn = ldap3.Connection(
                                self.server,
                                client_strategy='ASYNC',
                                authentication=ldap3.SASL,
                                sasl_mechanism='GSSAPI'
                            )
                        else:
                            self.conn = ldap3.Connection(
                                self.server,
                                client_strategy='ASYNC',
                                user=self.parameters['bind_dn'],
                                password=self.parameters['password']
                            )

                            if self.start_tls:
                                logger.debug('Performing STARTTLS...')
                                self.conn.open()
                                self.conn.start_tls()

                        if not self.conn.bind():
                            raise RuntimeError('Bind failed: wrong credentials')

                        self.directory.put_state(DirectoryState.BOUND)
                        continue
                    except BaseException as err:
                        self.directory.put_status(errno.ENXIO, '{0} <{1}>'.format(str(err), type(err).__name__))
                        self.directory.put_state(DirectoryState.FAILURE)
                        continue
                else:
                    if self.directory.state != DirectoryState.DISABLED:
                        self.directory.put_state(DirectoryState.EXITING)
                        self.conn.unbind()
                        self.directory.put_state(DirectoryState.DISABLED)
                        continue


def _init(context):
    context.register_plugin('ldap', LDAPPlugin)

    context.register_schema('LdapDirectoryParamsEncryption', {
        'type': 'string',
        'enum': ['OFF', 'SSL', 'TLS']
    })

    context.register_schema('LdapDirectoryParams', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['LdapDirectoryParams']},
            'server': {'type': 'string'},
            'base_dn': {'type': 'string'},
            'bind_dn': {'type': ['string', 'null']},
            'password': {'type': ['password', 'null']},
            'user_suffix': {'type': ['string', 'null']},
            'group_suffix': {'type': ['string', 'null']},
            'krb_principal': {'type': ['string', 'null']},
            'encryption': {'$ref': 'LdapDirectoryParamsEncryption'},
            'certificate': {'type': ['string', 'null']},
            'verify_certificate': {'type': 'boolean'}
        }
    })

    context.register_schema('LdapDirectoryStatus', {

    })
