#
# Copyright 2017 iXsystems, Inc.
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

import socket
import bsd
import pf
import netif
import ipaddress
import itertools
from typing import Optional
from task import Provider, query
from freenas.dispatcher.model import BaseStruct, BaseEnum
from freenas.utils import query as q


INADDR_ANY = ipaddress.ip_address('0.0.0.0')


class PortConsumerType(BaseEnum):
    SERVICE = 'SERVICE'
    VM = 'VM'
    CONTAINER = 'CONTAINER'
    OTHER = 'OTHER'


class PortAddressFamily(BaseEnum):
    INET = 'INET'
    INET6 = 'INET6'


class PortProtocol(BaseEnum):
    TCP = 'TCP'
    UDP = 'UDP'


class Port(BaseStruct):
    consumer_type: PortConsumerType
    consumer_name: str
    consumer_pid: Optional[int]
    af: PortAddressFamily
    protocol: PortProtocol
    port: int


class NetworkPortProvider(Provider):
    @query('Port')
    def query(self, filter=None, params=None):
        def collect_system():
            for proc in self.dispatcher.threaded(bsd.getprocs, bsd.ProcessLookupPredicate.PROC):
                seen_ports = set()
                for f in self.dispatcher.threaded(lambda: list(proc.files)):
                    if f.type != bsd.DescriptorType.SOCKET:
                        continue

                    if not f.peer_address:
                        continue

                    if f.peer_address[0] == INADDR_ANY:
                        continue

                    _, port = f.local_address
                    if port in seen_ports:
                        continue

                    try:
                        service = self.dispatcher.call_sync('serviced.job.get_by_pid', proc.pid, True)
                        type = 'SERVICE'
                        name = service['Label']
                    except:
                        type = 'OTHER'
                        name = proc.command

                    yield Port(
                        consumer_type=type,
                        consumer_pid=proc.pid,
                        consumer_name=name,
                        af=str(netif.AddressFamily(f.af)),
                        port=port,
                        protocol=PortProtocol.TCP if f.proto == socket.IPPROTO_TCP else PortProtocol.UDP
                    )

                    seen_ports.add(port)

        def collect_pf():
            p = pf.PF()
            for rule in p.get_rules('rdr'):
                if rule.label.startswith('container:'):
                    _, name = rule.label.split(':', maxsplit=1)
                    consumer = PortConsumerType.CONTAINER
                else:
                    name = rule.label
                    consumer = PortConsumerType.OTHER

                yield Port(
                    consumer_type=consumer,
                    consumer_pid=None,
                    consumer_name=name,
                    af=PortAddressFamily.INET,
                    port=rule.proxy_ports[0],
                    protocol=PortProtocol.TCP
                )

                yield Port(
                    consumer_type=consumer,
                    consumer_pid=None,
                    consumer_name=name,
                    af=PortAddressFamily.INET,
                    port=rule.proxy_ports[0],
                    protocol=PortProtocol.UDP
                )

        return q.query(
            itertools.chain(collect_system(), collect_pf()),
            *(filter or []),
            **(params or {})
        )


def _init(dispatcher, plugin):
    plugin.register_provider('network.port', NetworkPortProvider)
