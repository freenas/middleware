#!/usr/local/bin/python2.7
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

from __future__ import print_function
import os
import sys
import argparse
import logging
import subprocess
import errno
import threading
import netif
import time
import ipaddress
import io
import dhcp.client
import socket
import itertools
from bsd import setproctitle
from threading import Condition
from datastore import get_datastore, DatastoreException
from datastore.config import ConfigStore
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.rpc import RpcService, RpcException, private, generator
from freenas.utils.debug import DebugService
from freenas.utils import configure_logging, first_or_default
from freenas.serviced import checkin, push_status
from functools import reduce


DEFAULT_CONFIGFILE = '/usr/local/etc/middleware.conf'
INITIAL_DHCP_TIMEOUT = 180


def cidr_to_netmask(cidr):
    iface = ipaddress.ip_interface('0.0.0.0/{0}'.format(cidr))
    return str(str(iface.netmask))


def convert_aliases(entity):
    for i in entity.get('aliases', []):
        addr = netif.InterfaceAddress()
        iface = ipaddress.ip_interface('{0}/{1}'.format(i['address'], i['netmask']))
        addr.af = getattr(netif.AddressFamily, i.get('type', 'INET'))
        addr.address = ipaddress.ip_address(i['address'])
        addr.netmask = iface.netmask
        addr.broadcast = iface.network.broadcast_address

        if i.get('broadcast'):
            addr.broadcast = ipaddress.ip_address(i['broadcast'])

        if i.get('dest-address'):
            addr.dest_address = ipaddress.ip_address(i['dest-address'])

        yield addr


def convert_route(entity):
    if not entity:
        return None

    if entity['network'] == 'default':
        entity['network'] = '0.0.0.0'
        entity['netmask'] = '0.0.0.0'

    netmask = cidr_to_netmask(entity['netmask'])
    r = netif.Route(
        entity['network'],
        netmask,
        entity.get('gateway'),
        entity.get('interface')
    )

    r.flags.add(netif.RouteFlags.STATIC)

    if not r.netmask:
        r.flags.add(netif.RouteFlags.HOST)

    if r.gateway:
        r.flags.add(netif.RouteFlags.GATEWAY)

    return r


def default_route(gateway):
    if not gateway:
        return None

    gw = ipaddress.ip_address(gateway)
    if gw.version == 4:
        r = netif.Route('0.0.0.0', '0.0.0.0', gateway)

    elif gw.version == 6:
        r = netif.Route('::', '::', gateway)

    else:
        return

    r.flags.add(netif.RouteFlags.STATIC)
    r.flags.add(netif.RouteFlags.GATEWAY)
    return r


def describe_route(route):
    bits = bin(int(route.netmask)).count('1') if route.netmask else 0
    return '{0}/{1} via {2}'.format(route.network, bits, route.gateway)


def filter_routes(routes):
    """
    Filter out routes for loopback addresses and local subnets
    :param routes: routes list
    :return: filtered routes list
    """

    aliases = [i.addresses for i in list(netif.list_interfaces().values())]
    aliases = reduce(lambda x, y: x+y, aliases)
    aliases = [a for a in aliases if a.af == netif.AddressFamily.INET]
    aliases = [ipaddress.ip_interface('{0}/{1}'.format(a.address, a.netmask)) for a in aliases]

    for i in routes:
        if type(i.gateway) is str:
            continue

        if i.af != netif.AddressFamily.INET:
            continue

        found = True
        for a in aliases:
            if i.network in a.network:
                found = False
                break

        if found:
            yield i


def get_addresses(entity):
    return [ipaddress.ip_address(i['address']) for i in entity.get('aliases', [])]


class RoutingSocketEventSource(threading.Thread):
    def __init__(self, context):
        super(RoutingSocketEventSource, self).__init__()
        self.context = context
        self.client = context.client
        self.mtu_cache = {}
        self.flags_cache = {}
        self.link_state_cache = {}

    def build_cache(self):
        # Build a cache of certain interface states so we'll later know what has changed
        for i in list(netif.list_interfaces().values()):
            try:
                self.mtu_cache[i.name] = i.mtu
                self.flags_cache[i.name] = i.flags
                self.link_state_cache[i.name] = i.link_state
            except OSError as err:
                # Apparently interface doesn't exist anymore
                if err.errno == errno.ENXIO:
                    self.mtu_cache.pop(i.name, None)
                    self.flags_cache.pop(i.name, None)
                    self.link_state_cache.pop(i.name, None)
                else:
                    self.context.logger.warn('Building interface cache for {0} failed: {1}'.format(i.name, str(err)))

    def alias_added(self, message):
        pass

    def alias_removed(self, message):
        pass

    def run(self):
        rtsock = netif.RoutingSocket()
        rtsock.open()

        self.build_cache()

        while True:
            message = rtsock.read_message()

            if type(message) is netif.InterfaceAnnounceMessage:
                args = {'name': message.interface}

                if message.type == netif.InterfaceAnnounceType.ARRIVAL:
                    self.context.interface_attached(message.interface)
                    self.client.emit_event('network.interface.attached', args)

                if message.type == netif.InterfaceAnnounceType.DEPARTURE:
                    self.context.interface_detached(message.interface)
                    self.client.emit_event('network.interface.detached', args)

                # Interface arrival event might come before interface is fully instantiated.
                time.sleep(0.1)

                self.build_cache()

            if type(message) is netif.InterfaceInfoMessage:
                ifname = message.interface
                if ifname not in self.mtu_cache:
                    # Interface info sent before announce - ignore
                    continue

                if self.mtu_cache[ifname] != message.mtu:
                    self.client.emit_event('network.interface.mtu_changed', {
                        'interface': ifname,
                        'old_mtu': self.mtu_cache[ifname],
                        'new_mtu': message.mtu
                    })

                if self.link_state_cache[ifname] != message.link_state:
                    if message.link_state == netif.InterfaceLinkState.LINK_STATE_DOWN:
                        self.context.logger.warn('Link down on interface {0}'.format(ifname))
                        self.context.link_down(ifname)
                        self.client.emit_event('network.interface.link_down', {
                            'interface': ifname,
                        })

                    if message.link_state == netif.InterfaceLinkState.LINK_STATE_UP:
                        self.context.logger.warn('Link up on interface {0}'.format(ifname))
                        self.context.link_up(ifname)
                        self.client.emit_event('network.interface.link_up', {
                            'interface': ifname,
                        })

                if self.flags_cache[ifname] != message.flags:
                    if (netif.InterfaceFlags.UP in self.flags_cache) and (netif.InterfaceFlags.UP not in message.flags):
                        self.client.emit_event('network.interface.down', {
                            'interface': ifname,
                        })

                    if (netif.InterfaceFlags.UP not in self.flags_cache) and (netif.InterfaceFlags.UP in message.flags):
                        self.client.emit_event('network.interface.up', {
                            'interface': ifname,
                        })

                    self.client.emit_event('network.interface.flags_changed', {
                        'interface': ifname,
                        'old_flags': [f.name for f in self.flags_cache[ifname]],
                        'new_flags': [f.name for f in message.flags]
                    })

                self.client.emit_event('network.interface.changed', {
                    'operation': 'update',
                    'ids': [ifname]
                })

                self.build_cache()

            if type(message) is netif.InterfaceAddrMessage:
                entity = self.context.datastore.get_by_id('network.interfaces', message.interface)
                if entity is None:
                    continue

                # Skip messagess with empty address
                if not message.address:
                    continue

                # Skip 0.0.0.0 aliases
                if message.address == ipaddress.IPv4Address('0.0.0.0'):
                    continue

                addr = netif.InterfaceAddress()
                addr.af = netif.AddressFamily.INET
                addr.address = message.address
                addr.netmask = message.netmask
                addr.broadcast = message.dest_address

                if message.type == netif.RoutingMessageType.NEWADDR:
                    self.context.logger.warn('New alias added to interface {0} externally: {1}/{2}'.format(
                        message.interface,
                        message.address,
                        message.netmask
                    ))

                if message.type == netif.RoutingMessageType.DELADDR:
                    self.context.logger.warn('Alias removed from interface {0} externally: {1}/{2}'.format(
                        message.interface,
                        message.address,
                        message.netmask
                    ))

                self.client.emit_event('network.interface.changed', {
                    'operation': 'update',
                    'ids': [entity['id']]
                })

            if type(message) is netif.RoutingMessage:
                if message.errno != 0:
                    continue

                if message.type == netif.RoutingMessageType.ADD:
                    self.context.logger.info('Route to {0} added'.format(describe_route(message.route)))
                    self.client.emit_event('network.route.added', message.__getstate__())
                    with self.context.cv:
                        if str(message.route.network) == '0.0.0.0':
                            self.context.default_interface = message.route.interface
                            self.context.cv.notify_all()

                if message.type == netif.RoutingMessageType.DELETE:
                    self.context.logger.info('Route to {0} deleted'.format(describe_route(message.route)))
                    self.client.emit_event('network.route.deleted', message.__getstate__())

        rtsock.close()


@private
class ConfigurationService(RpcService):
    def __init__(self, context):
        self.context = context
        self.context.configure_network = self.configure_network
        self.logger = context.logger
        self.config = context.configstore
        self.datastore = context.datastore
        self.client = context.client

    def get_next_name(self, type):
        type_map = {
            'VLAN': 'vlan',
            'LAGG': 'lagg',
            'BRIDGE': 'bridge'
        }

        if type not in list(type_map.keys()):
            raise RpcException(errno.EINVAL, 'Invalid type: {0}'.format(type))

        ifaces = netif.list_interfaces()
        for i in range(2 if type == 'BRIDGE' else 0, 999):
            name = '{0}{1}'.format(type_map[type], i)

            if type == 'BRIDGE' and 'brg{0}'.format(i) in list(ifaces.keys()):
                continue

            if name not in list(ifaces.keys()) and not self.datastore.exists('network.interfaces', ('id', '=', name)):
                return name

        raise RpcException(errno.EBUSY, 'No free interfaces left')

    def get_dns_config(self):
        proc = subprocess.Popen(
            ['/sbin/resolvconf', '-l'],
            stdout=subprocess.PIPE
        )

        result = {
            'addresses': set(),
            'search': set()
        }

        out, err = proc.communicate()

        for i in out.splitlines():
            line = i.decode('utf-8')

            if len(line.strip()) == 0:
                continue

            if line[0] == '#':
                continue

            tokens = line.split()
            if tokens[0] == 'nameserver':
                result['addresses'].add(tokens[1])

            if tokens[0] == 'search':
                for i in tokens[1:]:
                    result['search'].add(i)

        return result

    def get_default_routes(self):
        routes = self.query_routes()
        default_ipv4 = first_or_default(lambda r: r['netmask'] == '0.0.0.0', routes)
        default_ipv6 = first_or_default(lambda r: r['netmask'] == '::', routes)
        return {
            'ipv4': default_ipv4['gateway'] if default_ipv4 else None,
            'ipv6': default_ipv6['gateway'] if default_ipv6 else None
        }

    def get_default_interface(self):
        routes = self.query_routes()
        default = first_or_default(lambda r: r['netmask'] == '0.0.0.0', routes)
        if default:
            return default['interface']

        return None

    def get_route(self, address):
        rt = netif.RoutingTable()
        return rt.get(ipaddress.ip_address(address))

    def wait_for_default_interface(self, timeout=None):
        with self.context.cv:
            return self.context.cv.wait_for(lambda: self.context.default_interface, timeout=timeout)

    def query_interfaces(self):
        def extend(name, iface):
            iface = iface.__getstate__()
            dhcp = self.context.dhcp_clients.get(name)

            if dhcp:
                iface['dhcp'] = dhcp.__getstate__()

            # Bridge interfaces don't report link state, so pretend they always have a link.
            if iface['name'].startswith('bridge'):
                iface['link_state'] = 'LINK_STATE_UP'

            return iface

        return {name: extend(name, i) for name, i in netif.list_interfaces().items()}

    def query_routes(self):
        rtable = netif.RoutingTable()
        return [r.__getstate__() for r in rtable.routes]

    @generator
    def configure_network(self):
        if self.config.get('network.autoconfigure'):
            # Try DHCP on each interface until we find lease. Mark failed ones as disabled.
            self.logger.warn('Network in autoconfiguration mode')
            for i in list(netif.list_interfaces().values()):
                entity = self.datastore.get_by_id('network.interfaces', i.name)
                if i.type == netif.InterfaceType.LOOP:
                    continue

                if i.name in ('mgmt0', 'nat0'):
                    continue

                if i.name.startswith(('brg', 'tap')):
                    continue

                msg = 'Trying to acquire DHCP lease on interface {0}...'.format(i.name)
                self.logger.info(msg)
                push_status(msg)
                i.up()

                if self.context.configure_dhcp(i.name, True, INITIAL_DHCP_TIMEOUT):
                    entity.update({
                        'enabled': True,
                        'dhcp': True
                    })

                    self.datastore.update('network.interfaces', entity['id'], entity)
                    self.config.set('network.autoconfigure', False)
                    self.logger.info('Successfully configured interface {0}'.format(i.name))
                    return
                else:
                    i.down()

            self.config.set('network.autoconfigure', False)
            yield errno.ENOENT, 'Failed to configure any network interface'
            return

        laggs = self.datastore.query_stream('network.interfaces', ('type', '=', 'LAGG'))
        vlans = self.datastore.query_stream('network.interfaces', ('type', '=', 'VLAN'))
        bridges = self.datastore.query_stream('network.interfaces', ('type', '=', 'BRIDGE'))
        physical = self.datastore.query_stream('network.interfaces', ('cloned', '=', False))

        for i in itertools.chain(physical, laggs, vlans, bridges):
            msg = 'Configuring interface {0}...'.format(i['id'])
            self.logger.info(msg)
            push_status(msg)
            try:
                yield from self.configure_interface(i['id'], False)
            except BaseException as e:
                self.logger.warning('Cannot configure {0}: {1}'.format(i['id'], str(e)), exc_info=True)

        # Are there any orphaned interfaces?
        for name, iface in list(netif.list_interfaces().items()):
            if not name.startswith(('vlan', 'lagg', 'bridge')):
                continue

            if not self.datastore.exists('network.interfaces', ('id', '=', name)):
                netif.destroy_interface(name)

        yield from self.configure_routes()
        yield from self.configure_dns()
        try:
            self.client.call_sync('service.restart', 'rtsold', timeout=300)
        except RpcException as err:
            yield err.code, err.message

        self.client.emit_event('network.changed', {
            'operation': 'update'
        })

    @generator
    def configure_routes(self):
        rtable = netif.RoutingTable()
        static_routes = filter_routes(rtable.static_routes)
        default_route_ipv4 = default_route(self.config.get('network.gateway.ipv4'))

        if not self.context.using_dhcp_for_gateway():
            # Default route was deleted
            if not default_route_ipv4 and rtable.default_route_ipv4:
                self.logger.info('Removing default route')
                try:
                    rtable.delete(rtable.default_route_ipv4)
                except OSError as e:
                    yield e.errno, 'Cannot remove default route: {0}'.format(str(e))

            # Default route was added
            elif not rtable.default_route_ipv4 and default_route_ipv4:
                self.logger.info('Adding default route via {0}'.format(default_route_ipv4.gateway))
                try:
                    rtable.add(default_route_ipv4)
                except OSError as e:
                    yield e.errno, 'Cannot add default route: {0}'.format(str(e))

            # Default route was changed
            elif rtable.default_route_ipv4 != default_route_ipv4:
                self.logger.info('Changing default route from {0} to {1}'.format(
                    rtable.default_route.gateway,
                    default_route_ipv4.gateway))

                try:
                    rtable.change(default_route_ipv4)
                except OSError as e:
                    yield e.errno, 'Cannot add default route: {0}'.format(str(e))

        else:
            self.logger.info('Not configuring default route as using DHCP')

        # Same thing for IPv6
        default_route_ipv6 = default_route(self.config.get('network.gateway.ipv6'))

        if not default_route_ipv6 and rtable.default_route_ipv6:
            # Default route was deleted
            self.logger.info('Removing default route')
            try:
                rtable.delete(rtable.default_route_ipv6)
            except OSError as e:
                yield e.errno, 'Cannot remove default route: {0}'.format(str(e))

        elif not rtable.default_route_ipv6 and default_route_ipv6:
            # Default route was added
            self.logger.info('Adding default route via {0}'.format(default_route_ipv6.gateway))
            try:
                rtable.add(default_route_ipv6)
            except OSError as e:
                yield e.errno, 'Cannot add default route: {0}'.format(str(e))

        elif rtable.default_route_ipv6 != default_route_ipv6:
            # Default route was changed
            self.logger.info('Changing default route from {0} to {1}'.format(
                rtable.default_route.gateway,
                default_route_ipv6.gateway))

            try:
                rtable.change(default_route_ipv6)
            except OSError as e:
                yield e.errno, 'Cannot add default route: {0}'.format(str(e))

        # Now the static routes...
        old_routes = set(static_routes)
        new_routes = set(convert_route(e) for e in self.datastore.query('network.routes'))

        for i in old_routes - new_routes:
            self.logger.info('Removing static route to {0}'.format(describe_route(i)))
            try:
                rtable.delete(i)
            except OSError as e:
                yield e.errno, 'Cannot remove static route to {0}: {1}'.format(describe_route(i), str(e))

        for i in new_routes - old_routes:
            self.logger.info('Adding static route to {0}'.format(describe_route(i)))
            try:
                rtable.add(i)
            except OSError as e:
                yield e.errno, 'Cannot add static route to {0}: {1}'.format(describe_route(i), str(e))

    @generator
    def configure_dns(self):
        self.logger.info('Starting DNS configuration')
        resolv = io.StringIO()
        dhcp_used = self.datastore.exists('network.interfaces', ('dhcp', '=', True))
        search = self.context.configstore.get('network.dns.search')

        try:
            proc = subprocess.Popen(
                ['/sbin/resolvconf', '-a', 'lo0'],
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE
            )

            if search:
                print('search {0}'.format(' '.join(search)), file=resolv)

            addrs = self.context.configstore.get('network.dns.addresses')
            for n in addrs:
                print('nameserver {0}'.format(n), file=resolv)

            proc.communicate(resolv.getvalue().encode('utf8'))
            proc.wait()
            resolv.close()

            if not self.context.configstore.get('network.dhcp.assign_dns') or not dhcp_used:
                # Purge DNS entries from all other interfaces
                out = subprocess.check_output(['/sbin/resolvconf', '-i']).decode('ascii')
                for i in filter(lambda i: i != 'lo0', out.split()):
                    subprocess.call(['/sbin/resolvconf', '-d', i])

            self.client.emit_event('network.dns.configured', {
                'addresses': addrs,
            })
        except subprocess.CalledProcessError:
            yield errno.EFAULT, 'Cannot configure DNS servers'

    @generator
    def configure_interface(self, name, restart_rtsold=True):
        entity = self.datastore.get_one('network.interfaces', ('id', '=', name))
        if not entity:
            raise RpcException(errno.ENXIO, "Configuration for interface {0} not found".format(name))

        try:
            iface = netif.get_interface(name)
        except KeyError:
            if entity.get('cloned'):
                netif.create_interface(entity['id'])
                iface = netif.get_interface(name)
            else:
                yield errno.ENOENT, "Interface {0} not found".format(name)
                return

        if not entity.get('enabled'):
            self.logger.info('Interface {0} is disabled'.format(name))
            return

        # check whether interface is a lagg member
        for j in netif.list_interfaces().values():
            try:
                if isinstance(j, netif.LaggInterface) and name in [p[0] for p in j.ports]:
                    lagg_member = True
                    break
            except OSError:
                continue
        else:
            lagg_member = False

        try:
            if netif.InterfaceFlags.UP not in iface.flags:
                self.logger.info('Bringing interface {0} up'.format(name))
                iface.up()

            # If it's VLAN, configure parent and tag
            if entity.get('type') == 'VLAN':
                vlan = entity.get('vlan')
                if vlan:
                    parent = vlan.get('parent')
                    tag = vlan.get('tag')

                    if parent != iface.parent or tag != iface.tag:
                        try:
                            tag = int(tag)
                            iface.unconfigure()
                            iface.configure(parent, tag)
                        except OSError as e:
                            yield e.errno, 'Failed to configure VLAN interface {0}: {1}'.format(name, str(e))

            # Configure protocol and member ports for a LAGG
            if entity.get('type') == 'LAGG':
                lagg = entity.get('lagg')
                if lagg:
                    new_protocol = getattr(netif.AggregationProtocol, lagg.get('protocol', 'FAILOVER'))
                    old_ports = set(p[0] for p in iface.ports)
                    new_ports = set(lagg['ports'])

                    if iface.protocol != new_protocol:
                        iface.protocol = new_protocol

                    for port in old_ports - new_ports:
                        iface.delete_port(port)

                    for port in lagg['ports']:
                        if port not in old_ports:
                            iface.add_port(port)

            # Configure member interfaces for a bridge
            if entity.get('type') == 'BRIDGE':
                bridge = entity.get('bridge')
                if bridge:
                    old_members = set(iface.members)
                    new_members = set(bridge['members'])

                    for port in old_members - new_members:
                        iface.delete_member(port)

                    for port in new_members - old_members:
                        iface.add_member(port)

            if entity.get('dhcp'):
                if name in self.context.dhcp_clients:
                    self.logger.info('Interface {0} already configured using DHCP'.format(name))
                else:
                    # Remove all existing aliases
                    for i in iface.addresses:
                        iface.remove_address(i)

                    self.logger.info('Trying to acquire DHCP lease on interface {0}...'.format(name))
                    if not self.context.configure_dhcp(name, True, INITIAL_DHCP_TIMEOUT):
                        yield errno.ENETUNREACH, 'Failed to configure interface {0} using DHCP'.format(name)
            else:
                if name in self.context.dhcp_clients:
                    self.logger.info('Stopping DHCP client on interface {0}'.format(name))
                    self.context.deconfigure_dhcp(name)

                iface = netif.get_interface(name)
                addresses = set(convert_aliases(entity))
                existing_addresses = set([a for a in iface.addresses if a.af != netif.AddressFamily.LINK])

                # Remove orphaned addresses
                for i in existing_addresses - addresses:
                    if i.af == netif.AddressFamily.INET6 and str(i.address).startswith('fe80::'):
                        # skip link-local IPv6 addresses
                        continue

                    self.logger.info('Removing address from interface {0}: {1}'.format(name, i))
                    iface.remove_address(i)

                # Add new or changed addresses
                for i in addresses - existing_addresses:
                    self.logger.info('Adding new address to interface {0}: {1}'.format(name, i))
                    iface.add_address(i)

            # nd6 stuff
            if entity.get('rtadv', False):
                iface.nd6_flags = iface.nd6_flags | {netif.NeighborDiscoveryFlags.ACCEPT_RTADV}
                if restart_rtsold:
                    self.client.call_sync('service.restart', 'rtsold', timeout=300)
            else:
                iface.nd6_flags = iface.nd6_flags - {netif.NeighborDiscoveryFlags.ACCEPT_RTADV}

            if entity.get('noipv6', False):
                iface.nd6_flags = iface.nd6_flags | {netif.NeighborDiscoveryFlags.IFDISABLED}
                iface.nd6_flags = iface.nd6_flags - {netif.NeighborDiscoveryFlags.AUTO_LINKLOCAL}
            else:
                iface.nd6_flags = iface.nd6_flags - {netif.NeighborDiscoveryFlags.IFDISABLED}
                iface.nd6_flags = iface.nd6_flags | {netif.NeighborDiscoveryFlags.AUTO_LINKLOCAL}

            if entity.get('mtu') and not isinstance(iface, netif.LaggInterface) and not lagg_member:
                try:
                    iface.mtu = entity['mtu']
                except OSError as err:
                    yield err.errno, 'Cannot set MTU of {0}: {1}'.format(name, str(err))

            if entity.get('media'):
                iface.media_subtype = entity['media']

            # vlan interfaces don't support capabilities
            if entity.get('capabilities') and not isinstance(iface, (netif.VlanInterface, netif.BridgeInterface)):
                caps = iface.capabilities
                for c in entity['capabilities'].get('add'):
                    caps.add(getattr(netif.InterfaceCapability, c))

                for c in entity['capabilities'].get('del'):
                    caps.remove(getattr(netif.InterfaceCapability, c))

                iface.capabilities = caps

        except OSError as err:
            yield err.errno, err.strerror

        self.client.emit_event('network.interface.configured', {
            'interface': name,
        })

    @generator
    def up_interface(self, name):
        yield from self.configure_interface(name)
        yield from self.configure_routes()

    def down_interface(self, name):
        try:
            iface = netif.get_interface(name)
        except NameError:
            raise RpcException(errno.ENOENT, "Interface {0} not found".format(name))

        # Remove all IP addresses from interface
        for addr in iface.addresses:
            if addr.af == netif.AddressFamily.LINK:
                continue

            try:
                iface.remove_address(addr)
            except:
                # Continue anyway
                pass

        iface.down()

    def renew_lease(self, name):
        self.logger.info('Renewing IP lease on {0}'.format(name))
        return self.context.renew_dhcp(name)


class Main(object):
    def __init__(self):
        self.config = None
        self.client = None
        self.datastore = None
        self.configstore = None
        self.rtsock_thread = None
        self.dhcp_clients = {}
        self.dhcp_lock = threading.RLock()
        self.configure_network = None
        self.logger = logging.getLogger('networkd')
        self.default_interface = None
        self.cv = Condition()

    def dhclient_pid(self, interface):
        path = os.path.join('/var/run', 'dhclient.{0}.pid'.format(interface))
        if not os.path.exists(path):
            return None

        try:
            with open(path) as f:
                pid = int(f.read().strip())
                return pid
        except (IOError, ValueError):
            return None

    def dhclient_running(self, interface):
        pid = self.dhclient_pid(interface)
        if not pid:
            return False

        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def configure_dhcp(self, interface, block=False, timeout=None):
        if interface in self.dhcp_clients:
            self.logger.info('Interface {0} already configured by DHCP'.format(interface))
            return True

        def bind(old_lease, lease):
            self.logger.info('{0} DHCP lease on {1} from {2}, valid for {3} seconds'.format(
                'Renewed' if old_lease else 'Acquired',
                interface,
                client.server_address,
                lease.lifetime,
                interface
            ))

            if old_lease is None or lease.client_ip != old_lease.client_ip:
                self.logger.info('Assigning IP address {0} to interface {1}'.format(lease.client_ip, interface))
                alias = lease.client_interface
                iface = netif.get_interface(interface)

                if old_lease:
                    try:
                        addr = first_or_default(lambda a: a.address == old_lease.client_ip, iface.addresses)
                        if addr:
                            iface.remove_address(addr)
                    except OSError as err:
                        self.logger.error('Cannot remove alias {0}: {1}'.format(old_lease.client_ip, err.strerror))

                try:
                    iface.add_address(netif.InterfaceAddress(netif.AddressFamily.INET, alias))
                except OSError as err:
                    self.logger.error('Cannot add alias to {0}: {1}'.format(interface, err.strerror))

            if lease.router and self.configstore.get('network.dhcp.assign_gateway'):
                try:
                    rtable = netif.RoutingTable()
                    newroute = default_route(lease.router)
                    if rtable.default_route_ipv4 != newroute:
                        if rtable.default_route_ipv4:
                            self.logger.info('DHCP default route changed from {0} to {1}'.format(
                                rtable.default_route_ipv4,
                                newroute
                            ))
                            rtable.delete(rtable.default_route_ipv4)
                            rtable.add(default_route(lease.router))
                        else:
                            self.logger.info('Adding default route via {0}'.format(lease.router))
                            rtable.add(default_route(lease.router))
                except OSError as err:
                    self.logger.error('Cannot configure default route: {0}'.format(err.strerror))

            if lease.dns_addresses and self.configstore.get('network.dhcp.assign_dns'):
                inp = []
                addrs = []
                proc = subprocess.Popen(
                    ['/sbin/resolvconf', '-a', interface],
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )

                for i in lease.dns_addresses:
                    # Filter out bogus DNS server addresses
                    if str(i) in ('127.0.0.1', '0.0.0.0', '255.255.255.255'):
                        continue

                    inp.append('nameserver {0}'.format(i))
                    addrs.append(i)

                if lease.domain_name:
                    inp.append('search {0}'.format(lease.domain_name))

                proc.communicate('\n'.join(inp).encode('ascii'))
                proc.wait()
                self.client.emit_event('network.dns.configured', {
                    'addresses': addrs,
                })
                self.logger.info('Updated DNS configuration')
            else:
                subprocess.call(['/sbin/resolvconf', '-d', interface])
                self.client.emit_event('network.dns.configured', {
                    'addresses': [],
                })
                self.logger.info('Deleted DNS configuration')

        def reject(reason):
            self.logger.info('DHCP request rejected on {0}: {1}'.format(interface, reason))
            self.deconfigure_dhcp(interface)
            if not block:
                t = threading.Timer(60, self.configure_dhcp, args=(interface,))
                t.start()

        def unbind(lease, reason):
            reasons = {
                dhcp.client.UnbindReason.EXPIRE: 'expired',
                dhcp.client.UnbindReason.REVOKE: 'revoked'
            }

            self.logger.info('DHCP lease on {0}: {1}'.format(interface, reasons.get(reason, 'revoked')))

        def state_change(state):
            self.client.emit_event('network.interface.changed', {
                'operation': 'update',
                'ids': [interface]
            })

        with self.dhcp_lock:
            client = dhcp.client.Client(interface, lambda: socket.gethostname().split('.')[0])
            client.on_bind = bind
            client.on_unbind = unbind
            client.on_reject = reject
            client.on_state_change = state_change
            client.start()
            self.dhcp_clients[interface] = client

        if block:
            ret = client.wait_for_bind(timeout)
            if ret is None:
                client.stop()
                del self.dhcp_clients[interface]

            return ret is not None

        return True

    def deconfigure_dhcp(self, interface):
        with self.dhcp_lock:
            client = self.dhcp_clients[interface]
            client.release()
            client.stop()
            del self.dhcp_clients[interface]

            try:
                iface = netif.get_interface(interface)
            except NameError:
                return

            # Remove all IP addresses from interface
            for addr in iface.addresses:
                if addr.af in (netif.AddressFamily.LINK, netif.AddressFamily.INET6):
                    continue

                try:
                    iface.remove_address(addr)
                except:
                    # Continue anyway
                    pass

    def renew_dhcp(self, interface):
        if interface not in self.dhcp_clients:
            raise RpcException(errno.ENXIO, 'Interface {0} is not configured for DHCP'.format(interface))

        if not self.dhcp_clients[interface].lease:
            raise RpcException(errno.ENOENT, 'Cannot renew without a lease')

        self.dhcp_clients[interface].request(renew=True, timeout=30)

    def link_down(self, name):
        if name in self.dhcp_clients:
            self.deconfigure_dhcp(name)

    def link_up(self, name):
        iface = self.datastore.get_by_id('network.interfaces', name)
        if not iface:
            return

        if iface.get('dhcp'):
            self.configure_dhcp(name)

    def interface_detached(self, name):
        self.logger.warn('Interface {0} detached from the system'.format(name))

    def interface_attached(self, name):
        self.logger.warn('Interface {0} attached to the system'.format(name))

    def using_dhcp_for_gateway(self):
        for i in self.datastore.query('network.interfaces'):
            if i.get('dhcp') and self.configstore.get('network.dhcp.assign_gateway'):
                return True

        return False

    def scan_interfaces(self):
        self.logger.info('Scanning available network interfaces...')
        existing = []

        # Add newly plugged NICs to DB
        for i in list(netif.list_interfaces().values()):
            existing.append(i.name)

            # We want only physical NICs
            if i.cloned:
                continue

            if i.name in ('mgmt0', 'nat0'):
                continue

            if i.name.startswith(('tap', 'brg')):
                continue

            if not self.datastore.exists('network.interfaces', ('id', '=', i.name)):
                self.logger.info('Found new interface {0} ({1})'.format(i.name, i.type.name))
                self.datastore.insert('network.interfaces', {
                    'enabled': False,
                    'id': i.name,
                    'name': None,
                    'cloned': False,
                    'type': i.type.name,
                    'dhcp': False,
                    'noipv6': False,
                    'rtadv': False,
                    'mtu': i.mtu,
                    'media': None,
                    'mediaopts': [],
                    'aliases': [],
                    'capabilities': {
                        'add': [],
                        'del': []
                    }
                })

        # Remove unplugged NICs from DB
        for i in self.datastore.query('network.interfaces', ('id', 'nin', existing), ('cloned', '=', False)):
            self.datastore.delete('network.interfaces', i['id'])

    def init_datastore(self):
        try:
            self.datastore = get_datastore(self.config)
        except DatastoreException as err:
            self.logger.error('Cannot initialize datastore: %s', str(err))
            sys.exit(1)

        self.configstore = ConfigStore(self.datastore)

    def connect(self, resume=False):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('networkd')
                self.client.enable_server()
                self.register_schemas()
                self.client.register_service('networkd.configuration', ConfigurationService(self))
                self.client.register_service('networkd.debug', DebugService())
                if resume:
                    self.client.resume_service('networkd.configuration')
                    self.client.resume_service('networkd.debug')

                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

    def init_dispatcher(self):
        def on_error(reason, **kwargs):
            if reason in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
                self.logger.warning('Connection to dispatcher lost')
                self.connect(resume=True)

        self.client = Client()
        self.client.on_error(on_error)
        self.connect()

    def init_routing_socket(self):
        self.rtsock_thread = RoutingSocketEventSource(self)
        self.rtsock_thread.start()

    def register_schemas(self):
        self.client.register_schema('NetworkAggregationProtocols', {
            'type': 'string',
            'enum': list(netif.AggregationProtocol.__members__.keys())
        })

        self.client.register_schema('NetworkLaggPortFlags', {
            'type': 'array',
            'items': {'$ref': 'NetworkLaggPortFlagsItems'}
        })

        self.client.register_schema('NetworkLaggPortFlagsItems', {
            'type': 'string',
            'enum': list(netif.LaggPortFlags.__members__.keys())
        })

        self.client.register_schema('NetworkInterfaceFlags', {
            'type': 'array',
            'items': {'$ref': 'NetworkInterfaceFlagsItems'}
        })

        self.client.register_schema('NetworkInterfaceFlagsItems', {
            'type': 'string',
            'enum': list(netif.InterfaceFlags.__members__.keys())
        })

        self.client.register_schema('NetworkInterfaceCapabilities', {
            'type': 'array',
            'items': {'$ref': 'NetworkInterfaceCapabilitiesItems'}
        })

        self.client.register_schema('NetworkInterfaceCapabilitiesItems', {
            'type': 'string',
            'enum': list(netif.InterfaceCapability.__members__.keys())
        })

        self.client.register_schema('NetworkInterfaceMediaopts', {
            'type': 'array',
            'items': {'$ref': 'NetworkInterfaceMediaoptsItems'}
        })

        self.client.register_schema('NetworkInterfaceMediaoptsItems', {
            'type': 'string',
            'enum': list(netif.InterfaceMediaOption.__members__.keys())
        })

        self.client.register_schema('NetworkInterfaceNd6Flag', {
            'type': 'array',
            'items': {'$ref': 'NetworkInterfaceNd6FlagItems'}
        })

        self.client.register_schema('NetworkInterfaceNd6FlagItems', {
            'type': 'string',
            'enum': list(netif.NeighborDiscoveryFlags.__members__.keys())
        })

        self.client.register_schema('NetworkInterfaceType', {
            'type': 'string',
            'enum': [
                'LOOPBACK',
                'ETHER',
                'VLAN',
                'BRIDGE',
                'LAGG'
            ]
        })

        self.client.register_schema('NetworkInterfaceDhcpState', {
            'type': 'string',
            'enum': [
                'INIT',
                'SELECTING',
                'REQUESTING',
                'INIT_REBOOT',
                'REBOOTING',
                'BOUND',
                'RENEWING',
                'REBINDING'
            ]
        })

        self.client.register_schema('NetworkInterfaceStatus', {
            'type': 'object',
            'properties': {
                'name': {'type': 'string'},
                'link_state': {'$ref': 'NetworkInterfaceStatusLinkstate'},
                'link_address': {'type': 'string'},
                'mtu': {'type': 'integer'},
                'media_type': {'type': 'string'},
                'media_subtype': {'type': 'string'},
                'active_media_type': {'type': 'string'},
                'active_media_subtype': {'type': 'string'},
                'media_options': {'$ref': 'NetworkInterfaceMediaopts'},
                'supported_media': {
                    'type': 'array',
                    'items': {'type': 'string'}
                },
                'cloned': {'type': 'boolean'},
                'capabilities': {'$ref': 'NetworkInterfaceCapabilities'},
                'flags': {'$ref': 'NetworkInterfaceFlags'},
                'dhcp': {
                    'type': 'object',
                    'properties': {
                        'state': {'$ref': 'NetworkInterfaceDhcpState'},
                        'server_address': {'type': 'string'},
                        'server_name': {'type': 'string'},
                        'lease_starts_at': {'type': 'datetime'},
                        'lease_ends_at': {'type': 'datetime'}
                    }
                },
                'aliases': {
                    'type': 'array',
                    'items': {'$ref': 'NetworkInterfaceAlias'}
                },
                'nd6_flags': {
                    'type': 'array',
                    'items': {'$ref': 'NetworkInterfaceNd6Flag'}
                },
                'ports': {
                    'oneOf': [
                        {'type': 'null'},
                        {
                            'type': 'array',
                            'members': {
                                'type': 'object',
                                'properties': {
                                    'name': {'type': 'string'},
                                    'flags': {'$ref': 'NetworkLaggPortFlags'}
                                }
                            }
                        }
                    ]
                },
                'members': {
                    'oneOf': [
                        {'type': 'null'},
                        {
                            'type': 'array',
                            'members': {'type': 'string'}
                        }
                    ]
                },
                'parent': {'type': ['string', 'null']},
                'tag': {'type': ['integer', 'null']}
            }
        })

        self.client.register_schema('NetworkInterfaceStatusLinkstate', {
            'type': 'string',
            'enum': list(netif.InterfaceLinkState.__members__.keys())
        })

    def checkin(self):
        checkin()

    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', metavar='CONFIG', default=DEFAULT_CONFIGFILE, help='Middleware config file')
        args = parser.parse_args()
        configure_logging('networkd', 'DEBUG')
        setproctitle('networkd')
        self.config = args.c
        self.init_datastore()
        self.init_dispatcher()
        self.scan_interfaces()
        self.init_routing_socket()
        self.client.resume_service('networkd.configuration')
        self.client.resume_service('networkd.debug')

        for i in self.configure_network():
            self.logger.info('Initial network configuration: {0}, {1}'.format(*i))

        self.checkin()
        self.logger.info('Started')
        self.client.wait_forever()

if __name__ == '__main__':
    m = Main()
    m.main()
