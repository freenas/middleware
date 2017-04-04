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

import psutil
import io
import os
import errno
import tempfile
import socket
import contextlib
from freenas.dispatcher.jsonenc import dumps, loads
from freenas.dispatcher.client import Client
from freenas.utils.url import wrap_address
from paramiko import RSAKey, AuthenticationException, SSHException
from task import TaskException


def first_or_default(f, iterable, default=None):
    i = list(filter(f, iterable))
    if i:
        return i[0]

    return default


def is_child(path, path2):
    return path.startswith(path2 + '/')


def split_dataset(dataset_path):
    pool = dataset_path.split('/')[0]
    return pool, dataset_path


def save_config(conf_path, name_mod, entry, file_perms=None, version=None):
    file_name = os.path.join(conf_path, f'.config-{name_mod}.json')

    if version:
        entry['%version'] = version

    with open(file_name, 'w', encoding='utf-8') as conf_file:
        conf_file.write(dumps(entry))

    if file_perms:
        with contextlib.suppress(OSError):
            os.chmod(file_name, file_perms)


def load_config(conf_path, name_mod, version=None):
    with open(os.path.join(conf_path, f'.config-{name_mod}.json'), 'r', encoding='utf-8') as conf_file:
        entry = loads(conf_file.read())
        if version and entry.get('%version') != version:
            raise ValueError(f'Unsupported version: got {entry.get("%version", "<none>")} instead of {version}')

        return entry


def delete_config(conf_path, name_mod):
    os.remove(os.path.join(conf_path, f'.config-{name_mod}.json'))


def get_freenas_peer_client(parent, remote):
    try:
        address = socket.gethostbyname(remote)
    except socket.error as err:
        raise TaskException(err.errno, '{0} is unreachable'.format(remote))

    host = parent.dispatcher.call_sync(
        'peer.query', [
            ('or', [
                ('credentials.address', '=', remote),
                ('credentials.address', '=', address),
            ]),
            ('type', '=', 'freenas')
        ],
        {'single': True}
    )
    if not host:
        raise TaskException(errno.ENOENT, 'There are no known keys to connect to {0}'.format(remote))

    with io.StringIO() as f:
        f.write(parent.configstore.get('peer.freenas.key.private'))
        f.seek(0)
        pkey = RSAKey.from_private_key(f)

    credentials = host['credentials']

    try:
        client = Client()
        with tempfile.NamedTemporaryFile('w') as host_key_file:
            host_key_file.write(remote + ' ' + credentials['hostkey'])
            host_key_file.flush()
            client.connect(
                'ws+ssh://freenas@{0}'.format(wrap_address(remote)),
                port=credentials['port'],
                host_key_file=host_key_file.name,
                pkey=pkey
            )
        client.login_service('replicator')
        return client

    except (AuthenticationException, SSHException):
        raise TaskException(errno.EAUTH, 'Cannot connect to {0}'.format(remote))
    except OSError as err:
        raise TaskException(errno.ECONNREFUSED, 'Cannot connect to {0}: {1}'.format(remote, err))


def call_task_and_check_state(client, name, *args):
    result = client.call_task_sync(name, *args)
    if result['state'] != 'FINISHED':
        raise TaskException(errno.EFAULT, 'Task failed: {0}'.format(
            result['error']['message']
        ))
    return result


def is_port_open(portnum, protocol='tcp', address=None):
    """
    protocol is one in:
    ['inet', 'inte4', 'inet6', 'tcp', 'tcp4', 'tcp6', 'udp', 'udp4', 'udp6', 'unix', 'all']
    see: http://pythonhosted.org/psutil/#psutil.net_connections for further explanation
    """
    for c in psutil.net_connections(kind=protocol):
        if address:
            if c.laddr[1] == int(portnum) and address == c.laddr[0]:
                return True

        else:
            if c.laddr[1] == int(portnum):
                return True

    return False
