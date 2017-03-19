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

import binascii
import uuid
import dns.resolver
import dns.exception
import krb5
from datetime import datetime
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn


class LdapQueryBuilder(object):
    def __init__(self, mappings=None):
        self.mappings = mappings or {}

    def _predicate(self, *args):
        if len(args) == 2:
            return self._joint_predicate(*args)

        if len(args) == 3:
            return self._operator_predicate(*args)

    def _operator_predicate(self, name, op, value):
        name = self.mappings.get(name, name)
        if name is None:
            return

        if name is True:
            return '(objectClass=*)'

        if op == '=':
            return '({0}={1})'.format(name, escape_filter_chars(str(value)))

        if op == '=*':
            return '({0}=*{1})'.format(name, escape_filter_chars(str(value)))

        if op in ('~', 'match'):
            return '({0}={1})'.format(name, str(value))

        if op == '!=':
            return '(!({0}={1}))'.format(name, escape_filter_chars(str(value)))

        if op == 'in':
            return self._joint_predicate('or', [
                (name, '=', str(v)) for v in value
            ])

    def _joint_predicate(self, op, value):
        if op == 'or':
            return '(|{0})'.format(''.join(filter(None.__ne__, (self._predicate(*i) for i in value))))

        if op == 'and':
            return '(&{0})'.format(''.join(filter(None.__ne__, (self._predicate(*i) for i in value))))

    def build_query(self, params):
        if len(params) == 1:
            return self._predicate(*params[0]) or '()'

        return self._joint_predicate('and', params)


def join_dn(*parts):
    return ','.join(parts)


def domain_to_dn(domain):
    return ','.join('dc={0}'.format(i) for i in domain.split('.'))


def dn_to_domain(dn):
    return '.'.join(i[1] for i in parse_dn(dn))


def obtain_or_renew_ticket(principal, password=None, renew_life=None, keytab=False):
    ctx = krb5.Context()
    cc = krb5.CredentialsCache(ctx)

    if have_ticket(principal):
        try:
            tgt = ctx.renew_tgt(principal, cc)
            cc.add(tgt)
        except krb5.KrbException:
            pass
        else:
            return

    if keytab:
        keytab = krb5.Keytab(ctx, '/etc/krb5.keytab')
        tgt = ctx.obtain_tgt_keytab(principal, keytab, renew_life=renew_life)
    elif password:
        tgt = ctx.obtain_tgt_password(principal, password, renew_life=renew_life)
    else:
        raise krb5.KrbException("Neither password nor keytab provided")

    if abs((tgt.starttime - datetime.now()).total_seconds()) > 300:
        raise krb5.KrbException("Clock skew too great")

    cc.add(tgt)


def have_ticket(principal):
    ctx = krb5.Context()
    cc = krb5.CredentialsCache(ctx)

    for i in cc.entries:
        if i.client == principal:
            return True

    return False


def get_srv_records(service, protocol, domain, server=None):
    try:
        resolver = dns.resolver.Resolver(configure=True)
        if server:
            resolver.nameservers = [server]

        answer = resolver.query('_{0}._{1}.{2}'.format(service, protocol, domain), dns.rdatatype.SRV)
        for i in answer:
            yield i.target
    except dns.exception.DNSException:
        return


def get_a_records(domain, server=None):
    try:
        resolver = dns.resolver.Resolver(configure=True)
        if server:
            resolver.nameservers = [server]

        answer = resolver.query(domain, dns.rdatatype.A)
        for i in answer:
            yield i.address
    except dns.exception.DNSException:
        return


def crc32(domain):
    return binascii.crc32(domain.encode('utf-8'))


def uuid2(checksum, id):
    return uuid.UUID(fields=(checksum, 0, 0, 0, 0, id), version=2)


def parse_uuid2(value):
    if isinstance(value, str):
        value = uuid.UUID(value)

    if value.version != 2:
        raise ValueError('Invalid UUID version')

    return value.fields[0], value.fields[5]
