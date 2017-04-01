#!/usr/bin/env python
# Copyright (c) 2015 iXsystems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
from freenas.dispatcher.client import Client
from logging import config
import argparse
import email
import email.parser
import logging
import sys
import socket

logger = logging.getLogger('find_alias_for_smtplib')


def main(*args):
    connection = Client()
    connection.connect('unix:')
    connection.login_service('smtp')

    parser = argparse.ArgumentParser(description='Process email')
    parser.add_argument('-i', dest='strip_leading_dot', action='store_false',
                        default=True, help='see sendmail(8) -i')
    parser.add_argument('-t', dest='parse_recipients', action='store_true',
                        default=False,
                        help='parse recipients from message')
    parser.usage = ' '.join(parser.format_usage().split(' ')[1:-1])
    parser.usage += ' [email_addr|user] ..'
    args, to_addrs = parser.parse_known_args()
    if not to_addrs and not args.parse_recipients:
        parser.exit(message=parser.format_usage())
    msg = sys.stdin.read()

    em_parser = email.parser.Parser()
    em = em_parser.parsestr(msg)
    if args.parse_recipients:
        # Strip away the comma based delimiters and whitespace.
        to_addrs = map(str.strip, em.get('To').split(','))

    if not to_addrs or not to_addrs[0]:
        to_addrs = ['root']

    margs = {}
    margs['extra_headers'] = dict(em)
    margs['extra_headers'].update({
        'X-Mailer': 'FreeNAS',
        'X-FreeNAS-Host': socket.gethostname(),
    })
    margs['subject'] = em.get('Subject')

    if em.is_multipart():
        margs['attachments'] = filter(
            lambda part: part.get_content_maintype() != 'multipart',
            em.walk()
        )
        margs['message'] = (
            'This is a MIME formatted message.  If you see '
            'this text it means that your email software '
            'does not support MIME formatted messages.')
    else:
        margs['message'] = ''.join(email.iterators.body_line_iterator(em))

    if to_addrs:
        margs['to'] = to_addrs

    connection.call_sync('alert.emitter.email.send', margs)
    connection.disconnect()


if __name__ == '__main__':
    config.dictConfig({
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '%(levelname)s %(module)s(%(process)d): %(message)s'
            },
        },
        'handlers': {
            'stdout': {
                'class': 'logging.StreamHandler',
                'stream': sys.stdout,
                'formatter': 'verbose',
            },
            'syslog': {
                'class': 'logging.handlers.SysLogHandler',
                'address': '/var/run/log',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            '': {
                'handlers': ['syslog', 'stdout'],
                'level': logging.DEBUG,
                'propagate': True,
            },
        }
    })

    main(*sys.argv[1:])
