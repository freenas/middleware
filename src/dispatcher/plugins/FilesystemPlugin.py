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

import errno
import os
import stat
import pwd
import grp
import bsd
from datetime import datetime
from bsd import acl
from freenas.dispatcher.rpc import RpcException, description, accepts, returns, pass_sender, private, generator
from freenas.dispatcher.rpc import SchemaHelper as h
from task import Provider, Task, TaskStatus, TaskWarning, TaskException, TaskDescription
from auth import FileToken
from freenas.utils import query as q
from freenas.utils.permissions import modes_to_oct, get_type


@description("Provides informations filesystem structure")
class FilesystemProvider(Provider):
    @description("Lists contents of given directory")
    @accepts(str)
    @returns(h.array(h.ref('Directory')))
    def list_dir(self, path):
        result = []
        if not os.path.isdir(path):
            raise RpcException(errno.ENOENT, 'Path {0} is not a directory'.format(path))

        for i in os.listdir(path):
            try:
                st = os.stat(os.path.join(path, i))
            except OSError:
                continue

            item = {
                'name': i,
                'type': get_type(st),
                'size': st.st_size,
                'modified': st.st_mtime
            }

            result.append(item)

        return result

    @accepts(str)
    @returns(h.ref('Stat'))
    def stat(self, path):
        try:
            st = os.stat(path, follow_symlinks=False)
            a = acl.ACL(file=path)
        except OSError as err:
            raise RpcException(err.errno, str(err))

        try:
            user = self.dispatcher.call_sync('dscached.account.getpwuid', st.st_uid)
            domain = q.get(user, 'origin.domain')
            at = '@' if domain else None
            username = f'{user["username"]}{at}{domain}'
        except RpcException:
            username = None

        try:
            group = self.dispatcher.call_sync('dscached.account.getgrgid', st.st_gid)
            domain = q.get(group, 'origin.domain')
            at = '@' if domain else None
            username = f'{group["name"]}{at}{domain}'
        except RpcException:
            groupname = None

        return {
            'path': path,
            'type': get_type(st),
            'atime': datetime.utcfromtimestamp(st.st_atime),
            'mtime': datetime.utcfromtimestamp(st.st_mtime),
            'ctime': datetime.utcfromtimestamp(st.st_ctime),
            'uid': st.st_uid,
            'user': username,
            'gid': st.st_gid,
            'group': groupname,
            'permissions': {
                'acl': self.dispatcher.threaded(a.__getstate__),
                'user': username,
                'group': groupname,
                'modes': {
                    'value': st.st_mode & 0o777,
                    'user': {
                        'read': bool(st.st_mode & stat.S_IRUSR),
                        'write': bool(st.st_mode & stat.S_IWUSR),
                        'execute': bool(st.st_mode & stat.S_IXUSR)
                    },
                    'group': {
                        'read': bool(st.st_mode & stat.S_IRGRP),
                        'write': bool(st.st_mode & stat.S_IWGRP),
                        'execute': bool(st.st_mode & stat.S_IXGRP)
                    },
                    'others': {
                        'read': bool(st.st_mode & stat.S_IROTH),
                        'write': bool(st.st_mode & stat.S_IWOTH),
                        'execute': bool(st.st_mode & stat.S_IXOTH)
                    },
                }
            }
        }

    @pass_sender
    @accepts(str)
    @returns(str)
    def download(self, path, sender):
        try:
            f = open(path, 'rb')
        except OSError as e:
            raise RpcException(e.errno, e)

        token = self.dispatcher.token_store.issue_token(FileToken(
            user=sender.user,
            lifetime=60,
            direction='download',
            file=f,
            name=os.path.basename(f.name),
            size=os.path.getsize(path)
        ))

        return token

    @pass_sender
    @accepts(str, h.one_of(int, None), str)
    @returns(str)
    def upload(self, dest_path, size, mode, sender):
        try:
            f = open(dest_path, 'wb')
        except OSError as e:
            raise RpcException(e.errno, e)

        token = self.dispatcher.token_store.issue_token(FileToken(
            user=sender.user,
            lifetime=60,
            direction='upload',
            file=f,
            name=os.path.basename(dest_path),
            size=size
        ))

        return token

    @accepts(str)
    @returns(h.array(h.ref('OpenFile')))
    @generator
    def get_open_files(self, path):
        for proc in self.dispatcher.threaded(bsd.getprocs, bsd.ProcessLookupPredicate.PROC):
            for f in self.dispatcher.threaded(lambda: list(proc.files)):
                if not f.path:
                    continue

                if f.path.startswith(path):
                    yield {
                        'pid': proc.pid,
                        'process_name': proc.command,
                        'path': f.path
                    }


@accepts(str)
@private
@description('Downloads a file')
class DownloadFileTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Downloading file'

    def describe(self, connection):
        return TaskDescription('Downloading file')

    def verify(self, connection):
        return []

    def run(self, connection):
        self.connection = connection
        self.connection.done.wait()

    def get_status(self):
        if not self.connection:
            return TaskStatus(0)

        percentage = (self.connection.bytes_done / self.connection.bytes_total) * 100
        return TaskStatus(percentage)


@accepts(str)
@private
@description('Uploads a file')
class UploadFileTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Uploading file'

    def describe(self, connection):
        return TaskDescription('Uploading file')

    def verify(self, connection):
        return []

    def run(self, connection):
        self.connection = connection
        self.connection.done.wait()

    def get_status(self):
        if not self.connection:
            return TaskStatus(0)

        percentage = (self.connection.bytes_done / self.connection.bytes_total) * 100
        return TaskStatus(percentage)


@accepts(str, h.ref('Permissions'), bool)
@description('Sets permissions')
class SetPermissionsTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Setting permissions'

    def describe(self, path, permissions, recursive=False):
        return TaskDescription('Setting permissions on path {name}', name=path)

    def verify(self, path, permissions, recursive=False):
        try:
            pool, ds, rest = self.dispatcher.call_sync('volume.decode_path', path)
            return ['zfs:{0}'.format(ds)]
        except RpcException:
            return []

    def run(self, path, permissions, recursive=False):
        if not os.path.exists(path):
            raise TaskException(errno.ENOENT, 'Path {0} does not exist'.format(path))

        if recursive and not os.path.isdir(path):
            raise TaskException(errno.EINVAL, 'Recursive specified, but {0} is not directory'.format(path))

        if permissions.get('user') or permissions.get('group'):
            user = permissions.get('user')
            group = permissions.get('group')
            uid = gid = -1

            if user:
                try:
                    user = self.dispatcher.call_sync('dscached.account.getpwnam', user)
                    uid = user['uid']
                except RpcException:
                    raise TaskException(errno.ENOENT, 'User {0} not found'.format(user))

            if group:
                try:
                    group = self.dispatcher.call_sync('dscached.group.getgrnam', group)
                    gid = group['gid']
                except KeyError:
                    raise TaskException(errno.ENOENT, 'Group {0} not found'.format(group))

            bsd.lchown(path, uid, gid, recursive)

        ds = None
        chmod_safe = True

        try:
            poolname, dsname, rest = self.dispatcher.call_sync('volume.decode_path', path)
            ds = self.dispatcher.call_sync('volume.dataset.query', [('id', '=', dsname)], {'single': True})
            chmod_safe = ds['permissions_type'] == 'PERM'
        except RpcException:
            pass

        if permissions.get('modes'):
            modes = permissions['modes']
            if modes.get('value'):
                modes = int(modes['value'])
            else:
                modes = modes_to_oct(modes)

            try:
                bsd.lchmod(path, modes, recursive)
            except OSError as err:
                if err.errno == errno.EPERM:
                    if chmod_safe:
                        self.add_warning(TaskWarning(err.errno, 'chmod() failed: {0}'.format(err.strerror)))
                else:
                    raise TaskException(err.errno, 'chmod() failed: {0}'.format(err.strerror))

        if permissions.get('acl'):
            a = acl.ACL()
            a.__setstate__(permissions['acl'])
            a.apply(path)
            if not recursive:
                return

            # Build second ACL, but with inherits removed. It will be applied on files
            b = acl.ACL()
            b.__setstate__(permissions['acl'])
            for i in b.entries:
                i.flags[acl.NFS4Flag.DIRECTORY_INHERIT] = False
                i.flags[acl.NFS4Flag.FILE_INHERIT] = False

            for root, dirs, files in os.walk(path):
                for n in files:
                    try:
                        b.apply(file=os.path.join(root, n))
                    except OSError:
                        pass

                for n in dirs:
                    try:
                        a.apply(file=os.path.join(root, n))
                    except OSError:
                        pass

        if ds:
            self.dispatcher.dispatch_event('zfs.dataset.changed', {
                'operation': 'update',
                'ids': [ds['id']]
            })

        self.dispatcher.dispatch_event('file.permissions.changed', {
            'path': path,
            'recursive': recursive,
            'permissions': permissions
        })


def _init(dispatcher, plugin):
    plugin.register_schema_definition('Stat', {
        'type': 'object',
        'properties': {
            'path': {'type': 'string'},
            'type': {'type': 'string'},
            'size': {'type': 'integer'},
            'atime': {'type': 'datetime'},
            'mtime': {'type': 'datetime'},
            'ctime': {'type': 'datetime'},
            'permissions': {'$ref': 'Permissions'}
        }
    })

    plugin.register_schema_definition('Permissions', {
        'type': 'object',
        'properties': {
            'user': {'type': ['string', 'null']},
            'group': {'type': ['string', 'null']},
            'modes': {'$ref': 'UnixPermissions'},
            'acl': {
                'type': ['array', 'null'],
                'items': {'$ref': 'AclEntry'}
            }
        }
    })

    plugin.register_schema_definition('UnixPermissions', {
        'type': 'object',
        'properties': {
            'value': {'type': ['integer', 'null']},
            'user': {'$ref': 'UnixModeTuple'},
            'group': {'$ref': 'UnixModeTuple'},
            'others': {'$ref': 'UnixModeTuple'}
        }
    })

    plugin.register_schema_definition('UnixModeTuple', {
        'type': 'object',
        'properties': {
            'read': {'type': 'boolean'},
            'write': {'type': 'boolean'},
            'execute': {'type': 'boolean'}
        }
    })

    plugin.register_schema_definition('AclEntry', {
        'type': 'object',
        'properties': {
            'tag': {'$ref': 'AclEntryTag'},
            'type': {'$ref': 'AclEntryType'},
            'id': {'type': ['string', 'null']},
            'name': {'type': ['string', 'null']},
            'perms': {'$ref': 'AclEntryPerms'},
            'flags': {'$ref': 'AclEntryFlags'},
            'text': {'type': ['string', 'null']}
        }
    })

    plugin.register_schema_definition('AclEntryTag', {
        'type': 'string',
        'enum': list(acl.ACLEntryTag.__members__.keys())
    })

    plugin.register_schema_definition('AclEntryType', {
        'type': 'string',
        'enum': list(acl.ACLEntryType.__members__.keys())
    })

    plugin.register_schema_definition('AclEntryPerms', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'READ_DATA': {'type': 'boolean'},
            'LIST_DIRECTORY': {'type': 'boolean'},
            'WRITE_DATA': {'type': 'boolean'},
            'ADD_FILE': {'type': 'boolean'},
            'APPEND_DATA': {'type': 'boolean'},
            'ADD_SUBDIRECTORY': {'type': 'boolean'},
            'READ_NAMED_ATTRS': {'type': 'boolean'},
            'WRITE_NAMED_ATTRS': {'type': 'boolean'},
            'EXECUTE': {'type': 'boolean'},
            'DELETE_CHILD': {'type': 'boolean'},
            'READ_ATTRIBUTES': {'type': 'boolean'},
            'WRITE_ATTRIBUTES': {'type': 'boolean'},
            'DELETE': {'type': 'boolean'},
            'READ_ACL': {'type': 'boolean'},
            'WRITE_ACL': {'type': 'boolean'},
            'SYNCHRONIZE': {'type': 'boolean'}
        }
    })

    plugin.register_schema_definition('AclEntryFlags', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'FILE_INHERIT': {'type': 'boolean'},
            'DIRECTORY_INHERIT': {'type': 'boolean'},
            'NO_PROPAGATE_INHERIT': {'type': 'boolean'},
            'INHERIT_ONLY': {'type': 'boolean'}
        }
    })

    plugin.register_schema_definition('OpenFile', {
        'type': 'object',
        'properties': {
            'pid': {'type': 'integer'},
            'process_name': {'type': 'string'},
            'path': {'type': 'string'}
        }
    })

    plugin.register_provider('filesystem', FilesystemProvider)
    plugin.register_task_handler('file.download', DownloadFileTask)
    plugin.register_task_handler('file.upload', UploadFileTask)
    plugin.register_task_handler('file.set_permissions', SetPermissionsTask)
