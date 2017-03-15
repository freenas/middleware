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
import time
import errno
import json
import logging
import redmine
import requests
import simplejson
from task import Task, Provider, TaskException, TaskDescription
from freenas.dispatcher import Password
from freenas.dispatcher.rpc import RpcException, accepts, description, returns
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.utils.password import unpassword


logger = logging.getLogger('SupportPlugin')

PROXY_ADDRESS = 'support-proxy.ixsystems.com'
BUGTRACKER_ADDRESS = 'https://bugs.freenas.org'
DEFAULT_DEBUG_DUMP_DIR = '/tmp'
REDMINE_PROJECT_NAME = 'freenas-10'

VERSION_CODES = {
    'PRE-ALPHA': 232,
    '9.10.1-U2': 377,
    'BETA': 234,
    'RELEASE': 272,
    'FUTURE': 237,
    'ALPHA2': 324,
    'ALPHA': 233,
    '10.0-SU1': 384,
    '10.1-ALPHA': 385,
    'TrueNAS 10': 365,
    'BETA2': 375
}


@description("Provides access support")
class SupportProvider(Provider):
    @accepts(str, Password)
    @returns(h.array(str))
    def categories(self, user, password):
        version = self.dispatcher.call_sync('system.info.version')
        sw_name = version.split('-')[0].lower()
        try:
            r = requests.post(
                'https://%s/%s/api/v1.0/categories' % (PROXY_ADDRESS, sw_name),
                data=json.dumps({
                    'user': user,
                    'password': unpassword(password),
                    'project': REDMINE_PROJECT_NAME,
                }),
                headers={'Content-Type': 'application/json'},
                timeout=10,
            )
            data = r.json()
        except simplejson.JSONDecodeError as e:
            logger.debug('Failed to decode ticket attachment response: %s', e.text)
            raise RpcException(errno.EINVAL, 'Failed to decode ticket response')
        except requests.ConnectionError as e:
            raise RpcException(errno.ENOTCONN, 'Connection failed: {0}'.format(str(e)))
        except requests.Timeout as e:
            raise RpcException(errno.ETIMEDOUT, 'Connection timed out: {0}'.format(str(e)))

        if 'error' in data:
            raise RpcException(errno.EINVAL, data['message'])

        return data

    @returns(h.array(str))
    def categories_no_auth(self):
        version = self.dispatcher.call_sync('system.info.version')
        sw_name = version.split('-')[0].lower()
        try:
            r = requests.post(
                'https://%s/%s/api/v1.0/categoriesnoauth' % (PROXY_ADDRESS, sw_name),
                data=json.dumps({'project': REDMINE_PROJECT_NAME}),
                headers={'Content-Type': 'application/json'},
                timeout=10,
            )
            data = r.json()
        except simplejson.JSONDecodeError as e:
            logger.debug('Failed to decode ticket attachment response: %s', r.text)
            raise RpcException(errno.EINVAL, 'Failed to decode ticket response')
        except requests.ConnectionError as e:
            raise RpcException(errno.ENOTCONN, 'Connection failed: {0}'.format(str(e)))
        except requests.Timeout as e:
            raise RpcException(errno.ETIMEDOUT, 'Connection timed out: {0}'.format(str(e)))

        if 'error' in data:
            raise RpcException(errno.EINVAL, data['message'])

        return data


@description("Submits a new support ticket")
@accepts(
    h.all_of(
        h.ref('SupportTicket'),
        h.required('subject', 'description', 'category', 'type', 'username', 'password'))
)
class SupportSubmitTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Submitting ticket'

    def describe(self, ticket):
        return TaskDescription('Submitting ticket')

    def verify(self, ticket):
        return ['system']

    def run(self, ticket):
        version = self.dispatcher.call_sync('system.info.version')
        attachments = []
        debug_file_name = os.path.join(
                DEFAULT_DEBUG_DUMP_DIR, version + '_' + time.strftime('%Y%m%d%H%M%S') + '.tar.gz'
        )

        try:
            rm_connection = redmine.Redmine(
                BUGTRACKER_ADDRESS,
                username=ticket['username'],
                password=unpassword(ticket['password'])
            )
            rm_connection.auth()

            for attachment in ticket.get('attachments', []):
                attachment = os.path.normpath(attachment)
                attachments.append({'path': attachment, 'filename': os.path.split(attachment)[-1]})
                if not os.path.exists(attachment):
                    raise TaskException(errno.ENOENT, 'File {} does not exists.'.format(attachment))

            if ticket.get('debug'):
                self.run_subtask_sync('debug.save_to_file', debug_file_name)
                attachments.append({'path': debug_file_name, 'filename': os.path.split(debug_file_name)[-1]})

            redmine_response = rm_connection.issue.create(
                project_id=REDMINE_PROJECT_NAME,
                subject=ticket['subject'],
                description=ticket['description'],
                category_id=ticket['category'],
                custom_fields=[{'id': 2, 'value': VERSION_CODES['BETA2']}],
                is_private=ticket.get('debug', False),
                tracker_id=1 if ticket['type'] == 'bug' else 2,
                uploads=attachments
            )
        except redmine.exceptions.AuthError:
            raise TaskException(errno.EINVAL, 'Invalid username or password')

        finally:
            if ticket.get('debug') and os.path.exists(debug_file_name):
                os.remove(debug_file_name)

        return redmine_response.id



def _depends():
    return ['SystemInfoPlugin']


def _init(dispatcher, plugin):
    plugin.register_schema_definition('SupportTicket', {
        'type': 'object',
        'properties': {
            'username': {'type': 'string'},
            'password': {'type': 'password'},
            'subject': {'type': 'string'},
            'description': {'type': 'string'},
            'category': {'type': 'string'},
            'type': {'type': 'string', 'enum': ['bug', 'feature']},
            'debug': {'type': 'boolean'},
            'attachments': {'type': 'array', 'items': {'type': 'string'}},
        },
        'additionalProperties': False,
        'required': ['username', 'password', 'subject', 'description', 'category', 'type', 'debug']
    })

    # Register events
    plugin.register_event_type('support.changed')

    # Register provider
    plugin.register_provider('support', SupportProvider)

    # Register tasks
    plugin.register_task_handler('support.submit', SupportSubmitTask)

