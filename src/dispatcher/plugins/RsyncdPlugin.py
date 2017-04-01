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
import re
import os
import pwd
from fcntl import flock, LOCK_EX, LOCK_NB, LOCK_UN
from gevent import subprocess
from tempfile import TemporaryFile
from utils import is_port_open

from datastore import DatastoreException
from datastore.config import ConfigNode
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns, private, generator
from task import (
    Task, ProgressTask, Provider, TaskException, query,
    ValidationException, VerifyException, TaskDescription
)

logger = logging.getLogger('RsyncdPlugin')


@description('Provides info about Rsyncd service configuration')
class RsyncdProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('ServiceRsyncd'))
    def get_config(self):
        return ConfigNode('service.rsyncd', self.configstore).__getstate__()


@description("Provides access to rsyncd modules database")
class RsyncdModuleProvider(Provider):
    @description("Lists rsyncd modules present in the system")
    @query('RsyncdModule')
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('rsyncd-module', *(filter or []), **(params or {}))


@private
@description('Configure Rsyncd service')
@accepts(h.ref('ServiceRsyncd'))
class RsyncdConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring Rsyncd service'

    def describe(self, rsyncd):
        return TaskDescription('Configuring Rsyncd service')

    def verify(self, rsyncd):
        if rsyncd.get('port') and rsyncd['port'] > 65535:
            raise ValidationException(errno.EINVAL, 'Port number cannot be greater than 65535')

        return ['system']

    def run(self, rsyncd):
        config = ConfigNode('service.rsyncd', self.configstore).__getstate__()

        if rsyncd.get('port') and is_port_open(rsyncd['port']):
            service_state = self.dispatcher.call_sync(
                'service.query',
                [('name', '=', 'rsyncd')],
                {'single': True, 'select': 'state'}
            )

            if not (service_state == "RUNNING" and rsyncd['port'] == config['port']):
                raise TaskException(errno.EINVAL, 'Provided port is already in use')

        try:
            node = ConfigNode('service.rsyncd', self.configstore)
            node.update(rsyncd)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'rsyncd')
            self.dispatcher.dispatch_event('service.rsyncd.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure Rsyncd: {0}'.format(str(e))
            )


@description("Create a rsync module in the system")
@accepts(h.all_of(
    h.ref('RsyncdModule'),
    h.required('name', 'path'),
))
class RsyncdModuleCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Adding rsync module'

    def describe(self, rsyncmod):
        return TaskDescription('Adding rsync module {name}', name=rsyncmod.get('name', '') or '')

    def verify(self, rsyncmod):
        errors = ValidationException()

        if re.search(r'[/\]]', rsyncmod['name']):
            errors.add((0, 'name'), 'The name cannot contain slash or a closing square backet.')

        if errors:
            raise errors

        return ['system']

    def run(self, rsyncmod):

        try:
            uuid = self.datastore.insert('rsyncd-module', rsyncmod)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'rsyncd')
            self.dispatcher.call_sync('service.restart', 'rsyncd')
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot add rsync module: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot regenerate rsyncd {0}'.format(str(e)))
        self.dispatcher.dispatch_event('rsyncd.module.changed', {
            'operation': 'create',
            'ids': [uuid]
        })
        return uuid


@description("Update a rsync module in the system")
@accepts(str, h.all_of(
    h.ref('RsyncdModule'),
))
class RsyncdModuleUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating rsync module'

    def describe(self, uuid, updated_fields):
        rsyncmod = self.datastore.get_by_id('rsyncd-module', uuid)
        return TaskDescription('Updating rsync module {name}', name=rsyncmod.get('name', '') if rsyncmod else '')

    def verify(self, uuid, updated_fields):
        return ['system']

    def run(self, uuid, updated_fields):

        rsyncmod = self.datastore.get_by_id('rsyncd-module', uuid)

        if rsyncmod is None:
            raise TaskException(errno.ENOENT, 'Rsync module {0} does not exist'.format(uuid))

        rsyncmod.update(updated_fields)

        if re.search(r'[/\]]', rsyncmod['name']):
            raise TaskException(errno.EINVAL, 'The name cannot contain slash or a closing square bracket.')

        try:
            self.datastore.update('rsyncd-module', uuid, rsyncmod)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'rsyncd')
            self.dispatcher.call_sync('service.restart', 'rsyncd')
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot update rsync module: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot regenerate rsyncd {0}'.format(str(e)))

        self.dispatcher.dispatch_event('rsyncd.module.changed', {
            'operation': 'update',
            'ids': [uuid]
        })


@description("Delete a rsync module in the system")
@accepts(str)
class RsyncdModuleDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting rsync module'

    def describe(self, uuid):
        rsyncmod = self.datastore.get_by_id('rsyncd-module', uuid)
        return TaskDescription('Deleting rsync module {name}', name=rsyncmod.get('name', '') if rsyncmod else '')

    def verify(self, uuid):
        return ['system']

    def run(self, uuid):
        rsyncmod = self.datastore.get_by_id('rsyncd-module', uuid)
        if rsyncmod is None:
            raise TaskException(errno.ENOENT, 'Rsync module {0} does not exist'.format(uuid))

        try:
            self.datastore.delete('rsyncd-module', uuid)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'rsyncd')
            self.dispatcher.call_sync('service.restart', 'rsyncd')
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot delete rsync module: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot regenerate rsyncd {0}'.format(str(e)))

        self.dispatcher.dispatch_event('rsyncd.module.changed', {
            'operation': 'delete',
            'ids': [uuid]
        })


def demote(user):
    """
    Helper function to call the subprocess as the specific user.
    Taken from: https://gist.github.com/sweenzor/1685717
    Pass the function 'set_ids' to preexec_fn, rather than just calling
    setuid and setgid. This will change the ids for that subprocess only"""

    def set_ids():
        if user:
            user_info = pwd.getpwnam(user)
            os.setgid(user_info.pw_gid)
            os.setuid(user_info.pw_uid)

    return set_ids


@private
@description("Runs an Rsync Copy Task with the specified arguments")
@accepts(h.ref('RsyncCopy'))
class RsyncCopyTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Running Rsync Copy Task with user specified arguments'

    def describe(self, params):
        return TaskDescription(
            'Running Rsync Copy Task {path} => {name}:{remote_path}',
            path=params.get('path', '') if params else '',
            name=params.get('user', '') + '@' + params.get('remote_host', '') if params else '',
            remote_path=params.get('remote_path', '') if params else ''
        )

    def verify(self, params):
        errors = ValidationException()

        path = params.get('path')
        rmode = params.get('rsync_mode')
        remote_path = params.get('remote_path')
        remote_host = params.get('remote_host')
        remote_module = params.get('remote_module')

        if path in [None, ''] or path.isspace():
            errors.add('path', errno.EINVAL, 'The Path is required')
        elif not os.path.exists(path):
            raise VerifyException(
                errno.ENOENT,
                "The specified path: '{0}'' does not exist".format(params.get('path'))
            )
        if (
            params.get('remote_host') in ['127.0.0.1', 'localhost'] and
            rmode == 'SSH' and
            remote_path is not None and
            not os.path.exists(remote_path)
           ):
            raise VerifyException(
                errno.ENOENT,
                "The specified path: '{0}'' does not exist".format(remote_path)
            )

        if rmode == 'SSH' and (remote_path in [None, ''] or remote_path.isspace()):
            errors.add('remote_path', errno.EINVAL, 'The Remote Path is required')
        elif rmode == 'MODULE' and (remote_module in [None, ''] or remote_module.isspace()):
            errors.add('remote_module', errno.EINVAL, 'The Remote Module is required')

        if remote_host in [None, ''] or remote_host.isspace():
            errors.add('remote_host', errno.EINVAL, 'A Remote Host needs to be specified')
        if errors:
            raise errors

        return []

    def run(self, params):
        try:
            pwd.getpwnam(params.get('user'))
        except KeyError:
            raise TaskException(
                errno.ENOENT, 'User {0} does not exist'.format(params.get('user'))
            )

        self.set_progress(0, 'Starting Rsync Task')
        with open(os.path.join(params['path'], '.lock'), 'wb+') as lockfile:
            # Lets try and get a lock on this path for the rsync task
            # but do not freak out if you do not get it
            try:
                flock(lockfile, LOCK_EX | LOCK_NB)
            except IOError:
                logger.warning('Rsync Task could not get a lock on {0}'.format(params['path']))

            # Execute Rsync Task here
            line = '/usr/local/bin/rsync --info=progress2 -h'
            rsync_properties = params.get('rsync_properties')
            if rsync_properties:
                if rsync_properties.get('recursive'):
                    line += ' -r'
                if rsync_properties.get('times'):
                    line += ' -t'
                if rsync_properties.get('compress'):
                    line += ' -z'
                if rsync_properties.get('archive'):
                    line += ' -a'
                if rsync_properties.get('preserve_permissions'):
                    line += ' -p'
                if rsync_properties.get('preserve_attributes'):
                    line += ' -X'
                if rsync_properties.get('delete'):
                    line += ' --delete-delay'
                if rsync_properties.get('delay_updates'):
                    line += ' --delay-updates'
                if rsync_properties.get('extra'):
                    line += ' {0}'.format(rsync_properties.get('extra'))

            remote_host = params.get('remote_host')
            remote_address = ''
            if '@' in remote_host:
                remote_address = remote_host
            else:
                remote_user = params.get('remote_user', params.get('user'))
                remote_address = '"{0}"@{1}'.format(remote_user, remote_host)

            if params.get('rsync_mode') == 'MODULE':
                if params.get('rsync_direction') == 'PUSH':
                    line += ' "{0}" {1}::"{2}"'.format(
                        params.get('path'),
                        remote_address,
                        params.get('remote_module'),
                    )
                else:
                    line += ' {0}::"{1}" "{2}"'.format(
                        remote_address,
                        params.get('remote_module'),
                        params.get('path'),
                    )
            else:
                line += ' -e "ssh -p {0} -o BatchMode=yes -o StrictHostKeyChecking=yes"'.format(
                    params.get('remote_ssh_port', 22)
                )
                if params.get('rsync_direction') == 'PUSH':
                    line += ' "{0}" {1}:\\""{2}"\\"'.format(
                        params.get('path'),
                        remote_address,
                        params.get('remote_path'),
                    )
                else:
                    line += ' {0}:\\""{1}"\\" "{2}"'.format(
                        remote_address,
                        params.get('remote_path'),
                        params.get('path'),
                    )

            if params.get('quiet'):
                line += ' > /dev/null 2>&1'

            # Starting rsync subprocess
            logger.debug('Rsync Copy Task Command: {0}'.format(line))
            # It would be nice to get the progess but not at the cost of
            # killing this task!

            # Note this TemporaryFile hack for the subprocess stdout is needed
            # because setting Popen's `stdout=subprocess.PIPE` does not allow
            # that sstdout to be seeked on. subprocess.PIPE only allows for
            # readline() and such read methods. stdout.readline() does not
            # allow for us to catch rsync's in-place progress updates which
            # are done with the '\r' character. It is also auto garbage collected.
            proc_stdout = TemporaryFile(mode='w+b', buffering=0)
            try:
                rsync_proc = subprocess.Popen(
                    line,
                    stdout=proc_stdout.fileno(),
                    stderr=subprocess.PIPE,
                    shell=True,
                    bufsize=0,
                    preexec_fn=demote(params.get('user'))
                )
                self.message = 'Executing Rsync Command'
                seek = 0
                old_seek = 0
                while rsync_proc.poll() is None:
                    proc_output = ''
                    proc_stdout.seek(seek)
                    try:
                        while True:
                            op_byte = proc_stdout.read(1).decode('utf8')
                            if op_byte == '':
                                # In this case break before incrementing `seek`
                                break
                            seek += 1
                            if op_byte == '\r':
                                break
                            proc_output += op_byte
                            seek += 1
                        if old_seek != seek:
                            old_seek = seek
                            self.message = proc_output.strip()
                            proc_output = proc_output.split(' ')
                            progress = [x for x in proc_output if '%' in x]
                            if len(progress):
                                try:
                                    self.set_progress(int(progress[0][:-1]))
                                except ValueError:
                                    pass
                    except Exception as e:
                        # Catch IOERROR Errno 9 which usually arises because
                        # of already closed fileobject being used here therby
                        # raising Bad File Descriptor error. In this case break
                        # and the outer while loop will check for rsync_proc.poll()
                        # to be None or not and DTRT
                        if e.errno == 9:
                            break
                        logger.debug("Parsing error in rsync task: {0}".format(str(e)))
            except Exception as e:
                flock(lockfile, LOCK_UN)
                self.message = 'Rsync Task Failed'
                raise TaskException(
                    errno.EIO,
                    'Rsync Task failed because of Error: {0}'.format(str(e))
                )
            if rsync_proc.returncode != 0:
                self.message = 'Rsync Task Failed'
                raise TaskException(
                    errno.EIO,
                    'Rsync Task returned with non-zero returncode. Error: {0}'.format(
                        rsync_proc.stderr.read())
                )
            # Finally lets unlock that lockfile, it does not fail
            # even if did not acquire the lock in the first place
            flock(lockfile, LOCK_UN)
            self.set_progress(100, 'Rsync Task Successfully Completed')


def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):
    # Register schemas
    plugin.register_schema_definition('ServiceRsyncd', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceRsyncd']},
            'enable': {'type': 'boolean'},
            'port': {
                'type': 'integer',
                'minimum': 1,
                'maximum': 65535
            },
            'auxiliary': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('RsyncdModule', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'description': {'type': ['string', 'null']},
            'path': {'type': 'string'},
            'mode': {'$ref': 'RsyncdModuleMode'},
            'max_connections': {'type': ['integer', 'null']},
            'user': {'type': 'string'},
            'group': {'type': 'string'},
            'hosts_allow': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'hosts_deny': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'auxiliary': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('RsyncdModuleMode', {
        'type': 'string',
        'enum': ['READONLY', 'WRITEONLY', 'READWRITE']
    })

    plugin.register_schema_definition('RsyncCopy', {
        'type': 'object',
        'properties': {
            'user': {'type': 'string'},
            'remote_user': {'type': 'string'},
            'remote_host': {'type': 'string'},
            'path': {'type': 'string'},
            'remote_path': {'type': 'string'},
            'remote_module': {'type': 'string'},
            'rsync_direction': {'$ref': 'RsyncCopyRsyncdirection'},
            'rsync_mode': {'$ref': 'RsyncCopyRsyncmode'},
            'remote_ssh_port': {'type': ['integer', 'null']},
            'rsync_properties': {
                'type': 'object',
                'properties': {
                    'recursive': {'type': 'boolean'},
                    'compress': {'type': 'boolean'},
                    'times': {'type': 'boolean'},
                    'archive': {'type': 'boolean'},
                    'delete': {'type': 'boolean'},
                    'preserve_permissions': {'type': 'boolean'},
                    'preserve_attributes': {'type': 'boolean'},
                    'delay_updates': {'type': 'boolean'},
                    'extra': {'type': 'string'}
                }
            },
            'quiet': {'type': 'boolean'},
        },
        'oneOf': [
            {'required': ['remote_path']},
            {'required': ['remote_module']}
        ],
        'required': ['user', 'path', 'remote_host', 'rsync_direction', 'rsync_mode'],
        'additionalProperties': False,
    })

    plugin.register_schema_definition('RsyncCopyRsyncdirection', {
        'type': 'string',
        'enum': ['PUSH', 'PULL']
    })

    plugin.register_schema_definition('RsyncCopyRsyncmode', {
        'type': 'string',
        'enum': ['MODULE', 'SSH']
    })

    # Register events
    plugin.register_event_type('rsyncd.module.changed')

    # Register providers
    plugin.register_provider("service.rsyncd", RsyncdProvider)
    plugin.register_provider("rsyncd.module", RsyncdModuleProvider)

    # Register tasks
    plugin.register_task_handler("service.rsyncd.update", RsyncdConfigureTask)
    plugin.register_task_handler("rsyncd.module.create", RsyncdModuleCreateTask)
    plugin.register_task_handler("rsyncd.module.update", RsyncdModuleUpdateTask)
    plugin.register_task_handler("rsyncd.module.delete", RsyncdModuleDeleteTask)
    plugin.register_task_handler("rsync.copy", RsyncCopyTask)
