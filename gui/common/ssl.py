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
import logging

from OpenSSL import crypto

log = logging.getLogger('common.ssl')

def create_self_signed_certificate(cert_info):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, cert_info['key_length'])

    cert = crypto.X509()
    cert.get_subject().C = cert_info['country']
    cert.get_subject().ST = cert_info['state']
    cert.get_subject().L =  cert_info['city']
    cert.get_subject().O =  cert_info['organization']
    cert.get_subject().CN =  cert_info['common']
    cert.get_subject().emailAddress = cert_info['email']

    #cert.set_serial_number(cert_info['serial'])

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(cert_info['lifetime'] * (60*60*24))

    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, str(cert_info['digest_algorithm']))

    return (cert, k)
