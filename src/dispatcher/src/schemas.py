#+
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


def register_general_purpose_schemas(dispatcher):
    dispatcher.register_schema_definition('IpAddress', {
        'anyOf': [
            {
                'type': 'string',
                'format': 'ipv4'
            },
            {
                'type': 'string',
                'format': 'ipv6'
            }
        ]
    })

    dispatcher.register_schema_definition('Ipv4Address', {
        'type': 'string',
        'format': 'ipv4'
    })

    dispatcher.register_schema_definition('Ipv6Address', {
        'type': 'string',
        'format': 'ipv6'
    })

    dispatcher.register_schema_definition('IsoDatetime', {
        'type': 'string',
        'format': 'date-time'
    })

    dispatcher.register_schema_definition('Email', {
        'type': 'string',
        'format': 'email'
    })

    dispatcher.register_schema_definition('ValidationError', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'path': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'code': {'type': 'integer'},
            'message': {'type': 'string'}
        }
    })

    dispatcher.register_schema_definition('Error', {
        'type': 'object',
        'properties': {
            'type': {'type': 'string'},
            'code': {'type': 'integer'},
            'stacktrace': {'type': 'string'},
            'message': {'type': 'string'},
            'extra': {
                'oneOf': [
                    {'type': 'null'},
                    {
                        'type': 'array',
                        'items': {'$ref': 'ValidationError'}
                    }
                ]
            }
        }
    })

    dispatcher.register_schema_definition('Rusage', {
        'type': 'object',
        'properties': {
            'ru_oublock': {'type': 'number'},
            'ru_msgsnd': {'type': 'number'},
            'ru_stime': {'type': 'number'},
            'ru_nsignals': {'type': 'number'},
            'ru_nswap': {'type': 'number'},
            'ru_utime': {'type': 'number'},
            'ru_majflt': {'type': 'number'},
            'ru_isrss': {'type': 'number'},
            'ru_inblock': {'type': 'number'},
            'ru_msgrcv': {'type': 'number'},
            'ru_idrss': {'type': 'number'},
            'ru_minflt': {'type': 'number'},
            'ru_nivcsw': {'type': 'number'},
            'ru_ixrss': {'type': 'number'},
            'ru_maxrss': {'type': 'number'},
            'ru_nvcsw': {'type': 'number'}
        }
    })

    dispatcher.register_schema_definition('Task', {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'args': {'type': 'object'},
            'id': {'type': 'integer'},
            'parent': {'type': ['integer', 'null']},
            'abortable': {'type': 'boolean'},
            'description': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'name': {'type': ['string', 'null']},
                    'format': {
                        'string': {'type': 'string'},
                        'args': {'type': 'object'}
                    }
                }
            },
            'debugger': {
                'oneOf': [
                    {
                        'type': 'array',
                        'items': {'type': 'string'}
                    },
                    {'type': 'null'}
                ]
            },
            'user': {'type': ['string', 'null']},
            'session': {'type': ['integer', 'null']},
            'resources': {'type': ['array', 'null']},
            'created_at': {'$ref': 'IsoDatetime'},
            'started_at': {
                'oneOf': [
                    {'type': 'null'},
                    {'$ref': 'IsoDatetime'}
                ]
            },
            'updated_at': {
                'oneOf': [
                    {'type': 'null'},
                    {'$ref': 'IsoDatetime'}
                ]
            },
            'finished_at': {
                'oneOf': [
                    {'type': 'null'},
                    {'$ref': 'IsoDatetime'}
                ]
            },
            'state': {
                'type': 'string',
                'enum': ['CREATED', 'WAITING', 'EXECUTING', 'ROLLBACK', 'FINISHED', 'FAILED', 'ABORTED']
            },
            'output': {'type': 'string'},
            'warnings': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'error': {
                'oneOf': [
                    {'$ref': 'error'},
                    {'type': 'null'}
                ]
            },
            'rusage':  {
                'oneOf': [
                    {'$ref': 'rusage'},
                    {'type': 'null'}
                ]
            }
        }
    })
