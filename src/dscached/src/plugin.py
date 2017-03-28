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

import enum
from freenas.dispatcher.rpc import convert_schema


def params(sch):
    def wrapped(fn):
        fn.params_schema = convert_schema(sch)
        return fn

    return wrapped


def status(sch):
    def wrapped(fn):
        fn.status_schema = convert_schema(sch)
        return fn

    return wrapped


class DirectoryState(enum.Enum):
    DISABLED = 1
    JOINING = 2
    FAILURE = 3
    BOUND = 4
    EXITING = 5


class DirectoryServicePlugin(object):
    @classmethod
    def normalize_parameters(cls, parameters):
        return parameters

    def getpwent(self, filter=None, params=None):
        raise NotImplementedError()

    def getpwuid(self, name):
        raise NotImplementedError()

    def getpwuuid(self, id):
        raise NotImplementedError()

    def getpwnam(self, uid):
        raise NotImplementedError()

    def getgrent(self, filter=None, params=None):
        raise NotImplementedError()

    def getgrnam(self, name):
        raise NotImplementedError()

    def getgrgid(self, gid):
        raise NotImplementedError()

    def getgruuid(self, id):
        raise NotImplementedError()

    def getsid(self, sid):
        raise NotImplementedError()

    def configure(self, *args, **kwargs):
        pass

    def get_kerberos_realm(self, parameters):
        return None

    def get_domain_sid(self):
        return None
