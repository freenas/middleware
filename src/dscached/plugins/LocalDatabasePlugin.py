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
import errno
from freenas.dispatcher import Password
from plugin import DirectoryServicePlugin, DirectoryState


class LocalDatabasePlugin(DirectoryServicePlugin):
    def __init__(self, context):
        def flush_users(ev):
            for i in ev['ids']:
                context.users_cache.flush(i)

        def flush_groups(ev):
            for i in ev['ids']:
                context.groups_cache.flush(i)

        self.context = context
        self.client = context.client
        self.datastore = context.datastore
        self.client.register_event_handler('user.changed', flush_users)
        self.client.register_event_handler('group.changed', flush_groups)

    def getpwent(self, filter=None, params=None):
        return self.datastore.query_stream('users', *(filter or []), **(params or {}))

    def getpwnam(self, name):
        return self.datastore.get_one('users', ('username', '=', name))

    def getpwuid(self, uid):
        return self.datastore.get_one('users', ('uid', '=', uid))

    def getpwuuid(self, uuid):
        return self.datastore.get_one('users', ('id', '=', uuid))

    def getgrent(self, filter=None, params=None):
        return self.datastore.query_stream('groups', *(filter or []), **(params or {}))

    def getgrnam(self, name):
        return self.datastore.get_one('groups', ('name', '=', name))

    def getgrgid(self, gid):
        return self.datastore.get_one('groups', ('gid', '=', gid))

    def getgruuid(self, uuid):
        return self.datastore.get_one('groups', ('id', '=', uuid))

    def change_password(self, user_name, password):
        user = self.datastore.get_one('users', ('username', '=', user_name))
        if not user:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        self.context.client.call_task_sync('user.update', user['id'], {
            'password': Password(password)
        })

    def configure(self, enable, directory):
        directory.put_state(DirectoryState.BOUND)
        return 'local'


def _init(context):
    context.register_plugin('local', LocalDatabasePlugin)
