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

import json
from freenas.utils import create_with_mode


def convert_rpm(rpm):
    if rpm == 'UNKNOWN':
        return '0'

    if rpm == 'SSD':
        return '1'

    return str(rpm)


def redact(config):
    for i in config['auth-group'].values():
        i['secret'] = 'REDACTED'
        i['peer-secret'] = 'REDACTED'

    return config


def generate_luns(context):
    result = {}

    for disk in context.datastore.query('simulator.disks'):
        extent = {
            'path': disk['path'],
            'blocksize': disk['block_size'],
            'serial': disk['serial'],
            'options': {
                'device-id': '{0} {1}'.format(disk['model'], disk['serial']),
                'vendor': disk['vendor'],
                'product': disk['model'],
                'naa': disk['naa'],
                'rpm': convert_rpm(disk['rpm']),
                'removable': 'on'
            }
        }

        result[disk['id']] = extent

    for share in context.client.call_sync('share.query', [('type', '=', 'iscsi'), ('enabled', '=', True)]):
        props = share['properties']
        padded_serial = '{:<31}'.format(props['serial']) if not props['xen_compat'] else props['serial']
        extent = {
            'path': share['filesystem_path'],
            'blocksize': props['block_size'],
            'serial': props['serial'],
            'options': {
                'device-id': 'SCSI Disk {0}'.format(padded_serial),
                'vendor': 'FreeNAS',
                'product': 'SCSI Disk',
                'revision': '0123',
                'naa': props['naa'],
                'readonly': 'on' if props['read_only'] else 'off',
                'rpm': convert_rpm(props['rpm'])
            }
        }

        if props.get('vendor_id'):
            extent['options']['vendor'] = props['vendor_id']

        if props.get('product_id'):
            extent['options']['product'] = props['product_id']

        if props.get('device_id'):
            extent['options']['device-id'] = props['device_id']

        if props.get('size'):
            extent['size'] = props['size']

        if props.get('ctl_lun'):
            extent['ctl-lun'] = props['ctl_lun']

        if props.get('tpc'):
            extent['options']['insescure_tpc'] = 'on'

        result[share['name']] = extent

    return result


def generate_targets(context):
    result = {}

    if context.datastore.exists('simulator.disks'):
        def generate_lun(i):
            idx, disk = i
            return {
                'number': idx,
                'name': disk['id']
            }

        result['naa.5000c50006815e48'] = {
            'port': 'camsim',
            'lun': list(map(generate_lun, enumerate(context.datastore.query('simulator.disks', ('online', '=', True)))))
        }

    for i in context.datastore.query('vm.scsi_ports'):
        def gen(entries):
            for l in entries:
                lun = context.datastore.get_by_id('shares', l['lun_id'])
                if not lun:
                    continue

                yield {
                    'number': l['number'],
                    'name': lun['name']
                }

        result['iqn.2005-10.org.freenas.virtio-port{0}'.format(i['number'])] = {
            'port': 'ioctl/{0}'.format(i['number']),
            'lun': list(gen(i['luns']))
        }

    for i in context.datastore.query('iscsi.targets'):
        target = {
            'lun': i['extents'],
            'auth-group': i['auth_group'],
            'portal-group': {
                'name': i['portal_group'],
                'auth-group-name': i['auth_group']
            }
        }

        if i.get('description'):
            target['alias'] = i['description']

        name = i['id']
        if not name.startswith(('iqn.', 'naa.', 'eui.')):
            name = ':'.join([context.configstore.get('service.iscsi.base_name'), name])

        result[name] = target

    return result


def generate_auth_groups(context):
    result = {}

    def generate_chap_user(user):
        return {
            'user': user['name'],
            'secret': user['secret']
        }

    def generate_mutual_chap_user(user):
        return {
            'user': user['name'],
            'secret': user['secret'],
            'mutual-user': user['peer_name'],
            'mutual-secret': user['peer_secret']
        }

    for i in context.datastore.query('iscsi.auth'):
        group = {
            'auth-type': i['type'].lower()
        }

        # Check if group is in use
        if not context.datastore.exists('iscsi.targets', ('auth_group', '=', i['id'])):
            continue

        if i.get('users'):
            if i['type'] == 'CHAP_MUTUAL':
                group['auth-type'] = 'chap-mutual'
                group['chap-mutual'] = list(map(generate_mutual_chap_user, i['users']))
            elif i['type'] == 'CHAP':
                group['chap'] = list(map(generate_chap_user, i['users']))

        if i.get('initiators'):
            group['initiator-name'] = i['initiators']

        if i.get('networks'):
            group['initiator-portal'] = i['networks']

        result[i['id']] = group

    return result


def generate_portal_groups(context):
    result = {
        'default': {
            'listen': ['0.0.0.0:3260'],
            'discovery-auth-group': 'no-authentication'
        }
    }

    if not context.configstore.get('service.iscsi.enable'):
        return result

    for i in context.datastore.query('iscsi.portals'):
        portal = {
            'listen': list(map(lambda l: '{0}:{1}'.format(l['address'], l['port']), i['listen'])),
            'discovery-auth-group': 'no-authentication'
        }

        if '0.0.0.0:3260' in portal['listen']:
            result.pop('default', None)

        if i.get('discovery_auth_group'):
            portal['discovery-auth-group'] = i['discovery_auth_group']

        if i.get('discovery_auth_method'):
            portal['discovery-auth-method'] = i['discovery_auth_method']

        result[i['id']] = portal

    return result


def run(context):
    config = {
        'lun': generate_luns(context),
        'target': generate_targets(context),
        'auth-group': generate_auth_groups(context),
        'portal-group': generate_portal_groups(context),
        'isns-server': context.configstore.get('service.iscsi.isns_servers')
    }

    with create_with_mode('/etc/ctl.conf', 0o600) as f:
        json.dump(config, f, indent=4)

    with create_with_mode('/etc/ctl.conf.shadow', 0o600) as f:
        json.dump(redact(config), f, indent=4)

    context.emit_event('etcd.file_generated', {
        'name': '/etc/ctl.conf'
    })
