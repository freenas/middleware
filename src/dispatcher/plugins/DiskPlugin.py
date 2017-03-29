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

import os
import re
import enum
import errno
import json
import glob
import logging
import tempfile
import base64
import gevent
import time
import libzfs
import contextlib
from gevent import subprocess
from xml.etree import ElementTree
from bsd import geom, getswapinfo
from datetime import datetime, timedelta
from freenas.utils import first_or_default, remove_non_printable, query as q
from cam import CamDevice, CamEnclosure, EnclosureStatus, ElementStatus
from cache import CacheStore
from lib.geom import confxml
from lib.system import system, SubprocessException
from task import (
    Provider, Task, ProgressTask, TaskStatus, TaskException, VerifyException,
    query, TaskDescription
)
from debug import AttachData, AttachCommandOutput
from freenas.dispatcher.rpc import RpcException, accepts, returns, description, private, SchemaHelper as h, generator
from freenas.dispatcher import Password

from pySMART import Device


EXPIRE_TIMEOUT = timedelta(hours=24)
SMART_CHECK_INTERVAL = 600  # in seconds (i.e. 10 minutes)
SMART_ALERT_MAP = {
    'WARN': ('SmartWarn', 'S.M.A.R.T status warning'),
    'FAIL': ('SmartFail', 'S.M.A.R.T status failing')
}

ZFS_TYPE_IDS = (
    '516e7cba-6ecf-11d6-8ff8-00022d09712b',  # FreeBSD
    '6a898cc3-1dd2-11b2-99a6-080020736631',  # macOS/Linux/Illumos
    '85d5e45d-237c-11e1-b4b3-e89a8f7fc3a7'   # MidnightBSD
)

diskinfo_cache = CacheStore()
logger = logging.getLogger('DiskPlugin')


class AcousticLevel(enum.IntEnum):
    DISABLED = 0
    MINIMUM = 1
    MEDIUM = 64
    MAXIMUM = 127


class SelfTestType(enum.Enum):
    SHORT = 'short'
    LONG = 'long'
    CONVEYANCE = 'conveyance'
    OFFLINE = 'offline'


def get_boot_mode():
    try:
        retval = subprocess.check_output(['/bin/kenv', 'grub.platform'],
                                         stderr=subprocess.DEVNULL).decode('utf8').rstrip()
    except:
        retval = "pc"
    return retval

@description('Provides information about disks')
class DiskProvider(Provider):
    @query('Disk')
    @generator
    def query(self, filter=None, params=None):
        def extend(disk):
            if disk.get('delete_at'):
                disk['online'] = False
            else:
                disk['online'] = self.is_online(disk['path'])
                disk['status'] = diskinfo_cache.get(disk['id'])

            disk['rname'] = 'disk:{0}'.format(disk['path'])
            return disk

        return q.query(
            self.datastore.query_stream('disks', callback=extend),
            *(filter or []),
            stream=True,
            **(params or {})
        )

    @accepts(str)
    @returns(bool)
    def is_online(self, name):
        return os.path.exists(name)

    @accepts(str)
    @returns(str)
    def partition_to_disk(self, part_name):
        # Is it disk name?
        d = get_disk_by_path(part_name)
        if d:
            return d['id']

        part = self.get_partition_config(part_name)
        return part['disk_id']

    @accepts(str)
    @returns(h.ref('DiskStatus'))
    def get_disk_config_by_id(self, id):
        disk = diskinfo_cache.get(id)
        if not disk:
            raise RpcException(errno.ENOENT, "Disk id: {0} not found".format(id))

        return disk

    @accepts(str)
    @returns(h.ref('DiskStatus'))
    def get_disk_config(self, name):
        disk = get_disk_by_path(name)
        if not disk:
            raise RpcException(errno.ENOENT, "Disk {0} not found".format(name))

        return disk

    @accepts(str)
    def get_partition_config(self, part_name):
        for name, disk in diskinfo_cache.itervalid():
            if 'partitions' not in disk:
                continue

            for part in disk['partitions']:
                if part_name in part['paths']:
                    result = part.copy()
                    result['disk'] = disk['path']
                    result['disk_id'] = disk['id']
                    return result

        raise RpcException(errno.ENOENT, "Partition {0} not found".format(part_name))

    @accepts(str, bool)
    def identify(self, id, on):
        disk = diskinfo_cache.get(id)
        if not disk:
            raise RpcException(errno.ENOENT, 'Disk {0} not found'.format(id))

        enclosure = self.dispatcher.call_sync(
            'disk.enclosure.query',
            [('id', '=', disk.get('enclosure'))],
            {'single': True}
        )
        if not enclosure:
            raise RpcException(errno.EINVAL, 'No enclosure found for disk {0}'.format(id))

        element = first_or_default(lambda e: e['disk_name'] == disk['path'], enclosure['devices'])
        if not element:
            raise RpcException(errno.EINVAL, 'Disk not found in enclosure')

        enc = CamEnclosure(os.path.join('/dev', enclosure['name']))
        dev = first_or_default(lambda d: d.index == element['index'], enc.devices)
        if not dev:
            raise RpcException(errno.EINVAL, 'Disk not found in enclosure')

        try:
            self.dispatcher.threaded(dev.identify, on, False)
        except OSError as err:
            raise RpcException(err.errno, err.strerror)

    @private
    def update_disk_cache(self, disk):
        with self.dispatcher.get_lock('diskcache:{0}'.format(disk)):
            update_disk_cache(self.dispatcher, disk)

    @accepts(str)
    def path_to_id(self, path):
        disk_info = self.dispatcher.call_sync(
            'disk.query',
            [
                ('or', [('path', '=', path), ('name', '=', path), ('id', '=', path)]),
                ('online', '=', True)
            ],
            {'single': True}
        )
        return disk_info['id'] if disk_info else None

    @private
    @accepts(h.array(str))
    @returns(h.array(h.object(
        properties={
            'path': str,
            'key_slot': int
        },
        additionalProperties=False
    )))
    def key_slots_by_paths(self, paths):
        result = []
        geom.scan()
        for p in paths:
            provider_path = self.dispatcher.call_sync(
                'disk.query',
                [('path', '=', p)],
                {'select': 'status.data_partition_path', 'single': True}
            )
            vdev_config = geom.geom_by_name('ELI', provider_path.strip('/dev')).config
            result.append({'path': p, 'key_slot': int(vdev_config.get('UsedKey'))})

        return result

    @private
    @accepts(str)
    @returns(bool)
    def is_geli_provider(self, path):
        id = self.dispatcher.call_sync('disk.path_to_id', path)
        provider_path = self.dispatcher.call_sync(
            'disk.query',
            [('id', '=', id)],
            {'select': 'status.data_partition_path', 'single': True}
        )
        if provider_path:
            geom.scan()
            return bool(geom.geom_by_name('ELI', provider_path.strip('/dev')))
        else:
            return False

    @accepts(str, h.one_of(str, None))
    @returns(h.one_of(str, None))
    def device_to_identifier(self, name, serial=None):
        return device_to_identifier(name, serial)


class EnclosureProvider(Provider):
    @query('Enclosure')
    @generator
    def query(self, filter=None, params=None):
        def get_devname(devnames):
            if not devnames:
                return None

            disk = get_disk_by_path(os.path.join('/dev', devnames[0]))
            if not disk:
                return None

            return disk['path']

        seen_ids = set()

        def collect():
            for sesdev in glob.glob('/dev/ses[0-9]*'):
                try:
                    dev = CamEnclosure(sesdev)
                    if dev.id in seen_ids:
                        continue

                    seen_ids.add(dev.id)
                    devices = self.dispatcher.threaded(lambda: list(dev.devices))
                    yield {
                        'id': dev.id,
                        'name': os.path.basename(sesdev),
                        'description': dev.name,
                        'status': [i.name for i in dev.status] if dev.status else ['UNKNOWN'],
                        'devices': [
                            {
                                'index': i.index,
                                'status': i.status.name,
                                'name': i.description,
                                'disk_name': get_devname(i.devnames)
                            }
                            for i in devices if i.status != ElementStatus.UNSUPPORTED
                        ]
                    }
                except OSError:
                    continue

        return q.query(collect(), *(filter or []), **(params or {}))


@description(
    "GPT formats the given disk with the filesystem type and parameters(optional) specified"
)
@accepts(str, str, h.object())
class DiskGPTFormatTask(Task):
    @classmethod
    def early_describe(cls):
        return "Formatting disk"

    def describe(self, id, fstype, params=None):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Formatting disk {name}", name=os.path.basename(disk['path']))

    def verify(self, id, fstype, params=None):
        disk = disk_by_id(self.dispatcher, id)
        if not disk:
            raise VerifyException(f'Disk {id} not found')

        if not get_disk_by_path(disk['path']):
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        if fstype not in ['freebsd-zfs']:
            raise VerifyException(errno.EINVAL, "Unsupported fstype {0}".format(fstype))

        return ['disk:{0}'.format(id)]

    def run(self, id, fstype, params=None):
        disk = disk_by_id(self.dispatcher, id)

        allocation = self.dispatcher.call_sync(
            'volume.get_disks_allocation',
            [disk['path']]
        ).get(disk['path'])

        if allocation and allocation['type'] != 'EXPORTED_VOLUME':
            raise TaskException(
                errno.EINVAL,
                "Cannot perform format operation on an allocated disk {0}".format(disk['path'])
            )

        if params is None:
            params = {}

        blocksize = params.pop('blocksize', 4096)
        swapsize = params.pop('swapsize', 2048)
        minswapsize = swapsize * 4 * 1024 * 1024
        bootcode = params.pop('bootcode', '/boot/pmbr-datadisk')
        mediasize_mb = disk['mediasize']

        try:
            system('/sbin/gpart', 'destroy', '-F', disk['path'])
        except SubprocessException:
            # ignore
            pass

        try:
            with self.dispatcher.get_lock('diskcache:{0}'.format(disk['path'])):
                system('/sbin/gpart', 'create', '-s', 'gpt', disk['path'])
                if swapsize > 0 and mediasize_mb > minswapsize:
                    system(
                        '/sbin/gpart', 'add', '-a', str(blocksize), '-b', '128',
                        '-s', '{0}M'.format(swapsize),
                        '-t', 'freebsd-swap', disk['path']
                    )
                    system('/sbin/gpart', 'add', '-a', str(blocksize), '-t', fstype, disk['path'])
                else:
                    system('/sbin/gpart', 'add', '-a', str(blocksize), '-b', '128', '-t', fstype, disk['path'])

                system('/sbin/gpart', 'bootcode', '-b', bootcode, disk['path'])

            self.dispatcher.call_sync('disk.update_disk_cache', disk['path'], timeout=120)
        except SubprocessException as err:
            raise TaskException(errno.EFAULT, 'Cannot format disk {0}: {1}'.format(disk['path'], err.err))


@description('Formats given disk to be bootable and capable to be included in the Boot Pool')
@accepts(str)
class DiskBootFormatTask(Task):
    @classmethod
    def early_describe(cls):
        return "Formatting bootable disk"

    def describe(self, id):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Formatting bootable disk {name}", name=disk['path'])

    def verify(self, id):
        disk = disk_by_id(self.dispatcher, id)
        if not get_disk_by_path(disk['path']):
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        return ['disk:{0}'.format(disk['path'])]

    def run(self, id):
        disk = disk_by_id(self.dispatcher, id)
        try:
            system('/sbin/gpart', 'destroy', '-F', disk['path'])
        except SubprocessException:
            # ignore
            pass
        boot_mode = get_boot_mode()
        try:
            system('/sbin/gpart', 'create', '-s', 'gpt', disk['path'])
            if boot_mode == "efi":
                system('/sbin/gpart', 'add', '-i', '1', '-t', 'efi', '-s', '100m', disk['path'])
                system('/sbin/newfs_msdos', '-F', '16', "{}p1".format(disk['path']))
            else:
                system('/sbin/gpart', 'add', '-t', 'bios-boot', '-i', '1', '-s', '512k', disk['path'])
            system('/sbin/gpart', 'add', '-t', 'freebsd-zfs', '-i', '2', '-a', '4k', disk['path'])
            system('/sbin/gpart', 'set', '-a', 'active', disk['path'])
        except SubprocessException as err:
            raise TaskException(errno.EFAULT, 'Cannot format disk: {0}'.format(err.err))


@description("Installs Bootloader (grub) on specified disk")
@accepts(str)
class DiskInstallBootloaderTask(Task):
    @classmethod
    def early_describe(cls):
        return "Installing bootloader on disk"

    def describe(self, id):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Installing bootloader on disk {name}", name=disk['path'])

    def verify(self, id):
        disk = disk_by_id(self.dispatcher, id)
        if not get_disk_by_path(disk['path']):
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        return ['disk:{0}'.format(id)]

    def run(self, id):
        def exec_hook():
            os.environ["GRUB_TERMINAL_OUTPUT"] = "gfxterm"
            os.environ["PATH"] = "{0}:/usr/local/bin:/usr/local/sbin".format(os.environ['PATH'])
        boot_mode = get_boot_mode()
        try:
            disk = disk_by_id(self.dispatcher, id)
            if boot_mode == "efi":
                system("/sbin/mount", "-t", "msdosfs", "{}p1".format(disk['path']), "/boot/efi")
                try:
                    subprocess.check_call(["/usr/local/sbin/grub-install", "--efi-directory=/boot/efi",
                                           "--removable", "--target=x86_64-efi", disk['path']],
                                          preexec_fn=exec_hook)
                finally:
                    try:
                        system("/sbin/umount", "/boot/efi")
                    except:
                        pass
            else:
                system('/usr/local/sbin/grub-install', '--modules=zfs part_gpt', disk['path'])
            subprocess.check_call(['/usr/local/sbin/grub-mkconfig', '-o', '/boot/grub/grub.cfg'],
                                  preexec_fn=exec_hook)
                                
        except SubprocessException as err:
            raise TaskException(errno.EFAULT, 'Cannot install GRUB: {0}'.format(err.err))


@description("Erases the given Disk with erasure method specified (default: QUICK)")
@accepts(str, h.ref('DiskEraseMethod'))
class DiskEraseTask(Task):
    def __init__(self, dispatcher):
        super(DiskEraseTask, self).__init__(dispatcher)
        self.started = False
        self.mediasize = 0
        self.remaining = 0

    @classmethod
    def early_describe(cls):
        return "Erasing disk"

    def describe(self, id, erase_method=None):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription(
            "Erasing disk {name} with method {method}",
            name=disk['path'],
            method=erase_method if erase_method else 'QUICK'
        )

    def verify(self, id, erase_method=None):
        disk = disk_by_id(self.dispatcher, id)
        if not disk:
            raise VerifyException(errno.ENOENT, f"Disk {id} not found")

        return [f'disk:{id}']

    def run(self, id, erase_method=None):
        disk = disk_by_id(self.dispatcher, id)

        allocation = self.dispatcher.call_sync(
            'volume.get_disks_allocation',
            [disk['path']]
        ).get(disk['path'])

        if allocation and allocation['type'] != 'EXPORTED_VOLUME':
            raise TaskException(
                errno.EINVAL,
                "Cannot perform erase operation on an allocated disk {0}".format(disk['path'])
            )

        with contextlib.suppress(OSError):
            libzfs.clear_label(disk['path'])

        try:
            self.dispatcher.call_sync('disk.update_disk_cache', disk['path'], timeout=120)
            diskinfo = self.dispatcher.call_sync('disk.get_disk_config', disk['path'])
            if diskinfo.get('partitions'):
                system('/sbin/gpart', 'destroy', '-F', disk['path'])
        except SubprocessException as err:
            raise TaskException(errno.EFAULT, 'Cannot erase disk: {0}'.format(err.err))

        if not erase_method:
            erase_method = 'QUICK'

        zeros = b'\0' * (1024 * 1024)
        fd = os.open(disk['path'], os.O_WRONLY)

        if erase_method == 'QUICK':
            os.write(fd, zeros)
            os.lseek(fd, diskinfo['mediasize'] - len(zeros), os.SEEK_SET)
            os.write(fd, zeros)

        if erase_method in ('ZEROS', 'RANDOM'):
            self.mediasize = diskinfo['mediasize']
            self.remaining = self.mediasize
            self.started = True

            while self.remaining > 0:
                garbage = zeros if erase_method == 'ZEROS' else os.urandom(1024 * 1024)
                amount = min(len(garbage), self.remaining)
                os.write(fd, garbage[:amount])
                self.remaining -= amount

        os.close(fd)

    def get_status(self):
        if not self.started:
            return TaskStatus(0, 'Erasing disk...')

        return TaskStatus((self.mediasize - self.remaining) / float(self.mediasize), 'Erasing disk...')


@description("Configures online disk parameters")
@accepts(
    str,
    h.all_of(
        h.ref('Disk'),
        h.no(h.required('name', 'serial', 'path', 'id', 'mediasize', 'status'))
    )
)
class DiskConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return "Configuring disk"

    def describe(self, id, updated_fields):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Configuring disk {name}", name=disk['path'])

    def verify(self, id, updated_fields):
        disk = disk_by_id(self.dispatcher, id)
        if not disk:
            raise VerifyException(errno.ENOENT, 'Disk {0} not found'.format(id))

        return ['disk:{0}'.format(id)]

    def run(self, id, updated_fields):
        disk = self.datastore.get_by_id('disks', id)

        if not self.dispatcher.call_sync('disk.is_online', disk['path']):
            raise TaskException(errno.EINVAL, 'Cannot configure offline disk')

        smart_enabled_val = updated_fields.pop('smart', None)
        disk.update(updated_fields)
        self.datastore.update('disks', disk['id'], disk)

        if {'standby_mode', 'apm_mode', 'acoustic_level'} & set(updated_fields):
            configure_disk(self.datastore, id)

        if smart_enabled_val is not None:
            disk_status = self.dispatcher.call_sync('disk.get_disk_config_by_id', id)
            if not disk_status['smart_info']['smart_capable']:
                raise TaskException(errno.EINVAL, 'Disk is not SMART capable')

            device_smart_handle = Device(disk_status['gdisk_name'])
            if smart_enabled_val != device_smart_handle.smart_enabled:
                toggle_result = (None, '')
                toggle_result = device_smart_handle.smart_toggle(
                    'on' if smart_enabled_val else 'off'
                )
                if not toggle_result[0]:
                    raise TaskException(
                        errno.EINVAL,
                        "Tried to toggle {0}".format(disk['path']) +
                        " SMART enabled to: {0} and failed with error: {1}".format(
                            smart_enabled_val,
                            toggle_result[1]
                        )
                    )
                disk.update({'smart': smart_enabled_val})
            self.dispatcher.call_sync('disk.update_disk_cache', disk['path'], timeout=120)

        self.dispatcher.dispatch_event('disk.changed', {
            'operation': 'update',
            'ids': [disk['id']]
        })


@description("Deletes offline disk configuration from database")
@accepts(str)
class DiskDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting offline disk configuration"

    def describe(self, id):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Deleting offline disk {name} configuration", name=disk['path'])

    def verify(self, id):
        disk = self.datastore.get_by_id('disks', id)

        if not disk:
            raise VerifyException(errno.ENOENT, 'Disk {0} not found'.format(id))

        return ['disk:{0}'.format(id)]

    def run(self, id):
        disk = self.datastore.get_by_id('disks', id)

        if self.dispatcher.call_sync('disk.is_online', disk['path']):
            raise TaskException(errno.EINVAL, 'Cannot delete online disk')

        self.datastore.delete('disks', id)


@private
@accepts(str, h.ref('DiskAttachParams'))
@description('Initializes GELI encrypted partition')
class DiskGELIInitTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating encrypted partition"

    def describe(self, id, params=None):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Creating encrypted partition for {name}", name=os.path.basename(disk['path']))

    def verify(self, id, params=None):
        disk = disk_by_id(self.dispatcher, id)
        if params is None:
            params = {}

        if not disk:
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        if not ('key' in params or 'password' in params):
            raise VerifyException(errno.EINVAL, "At least one of key, password have to be specified for encryption")

        return ['disk:{0}'.format(id)]

    def run(self, id, params=None):
        if params is None:
            params = {}
        key = base64.b64decode(params.get('key', '') or '')
        password = params.get('password')
        disk_info = disk_by_id(self.dispatcher, id)
        disk_status = disk_info.get('status', None)
        if disk_status is not None:
            data_partition_path = disk_status.get('data_partition_path')
        else:
            raise TaskException(errno.EINVAL, 'Cannot get disk status for: {0}'.format(disk_info['path']))

        try:
            system('/sbin/geli', 'kill', data_partition_path)
        except SubprocessException:
            # ignore
            pass

        with tempfile.NamedTemporaryFile('wb') as keyfile:
            with tempfile.NamedTemporaryFile('w', encoding='utf-8') as passfile:
                keyfile.write(key)
                keyfile.flush()
                if isinstance(password, Password):
                    passfile.write(password.secret)
                    passfile.flush()
                try:
                    if isinstance(password, Password) and key:
                        system('/sbin/geli', 'init', '-s', str(4096), '-K', keyfile.name, '-J', passfile.name,
                               '-B none', data_partition_path)
                    elif key:
                        system('/sbin/geli', 'init', '-s', str(4096), '-K', keyfile.name, '-P', '-B none',
                               data_partition_path)
                    else:
                        system('/sbin/geli', 'init', '-s', str(4096), '-J', passfile.name, '-B none', data_partition_path)
                except SubprocessException as err:
                    raise TaskException(errno.EFAULT, 'Cannot init encrypted partition: {0}'.format(err.err))


@private
@accepts(str, h.ref('DiskSetKeyParams'))
@description('Sets new GELI user key in specified slot')
class DiskGELISetUserKeyTask(Task):
    @classmethod
    def early_describe(cls):
        return "Setting new key for encrypted partition"

    def describe(self, id, params=None):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Setting new key for encrypted partition on {name}", name=os.path.basename(disk['path']))

    def verify(self, id, params=None):
        disk = disk_by_id(self.dispatcher, id)
        if not disk:
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        if not ('key' in params or 'password' in params):
            raise VerifyException(errno.EINVAL, "At least one of key, password have to be specified for encryption")

        if params.get('slot', None) not in [0, 1]:
            raise VerifyException(errno.EINVAL, "Chosen key slot value {0} is not in valid range [0-1]".
                                  format(params.get('slot', None)))

        return ['disk:{0}'.format(id)]

    def run(self, id, params=None):
        if params is None:
            params = {}
        key = base64.b64decode(params.get('key', '') or '')
        password = params.get('password')
        slot = params.get('slot', 0)
        disk_info = disk_by_id(self.dispatcher, id)
        disk_status = disk_info.get('status')
        if disk_status:
            data_partition_path = os.path.join('/dev/gptid/', disk_status.get('data_partition_uuid'))
        else:
            raise TaskException(errno.EINVAL, 'Cannot get disk status for: {0}'.format(disk_info['path']))

        with tempfile.NamedTemporaryFile('wb') as keyfile:
            with tempfile.NamedTemporaryFile('w', encoding='utf-8') as passfile:
                keyfile.write(key)
                keyfile.flush()
                if isinstance(password, Password):
                    passfile.write(password.secret)
                    passfile.flush()
                try:
                    if isinstance(password, Password) and key:
                        system('/sbin/geli', 'setkey', '-K', keyfile.name, '-J', passfile.name,
                               '-n', str(slot), data_partition_path)
                    elif key:
                        system('/sbin/geli', 'setkey', '-K', keyfile.name, '-P', '-n', str(slot),
                               data_partition_path)
                    else:
                        system('/sbin/geli', 'setkey', '-J', passfile.name, '-n', str(slot), data_partition_path)
                except SubprocessException as err:
                    raise TaskException(errno.EFAULT, 'Cannot set new key for encrypted partition: {0}'.format(err.err))


@private
@accepts(str, int)
@description('Deletes GELI user key entry from a given slot')
class DiskGELIDelUserKeyTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting key of encrypted partition"

    def describe(self, id, slot):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Deleting key of encrypted partition on {name}", name=os.path.basename(disk['path']))

    def verify(self, id, slot):
        disk = disk_by_id(self.dispatcher, id)
        if not disk:
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        if slot not in [0, 1]:
            raise VerifyException(errno.EINVAL, "Chosen key slot value {0} is not in valid range [0-1]".format(slot))

        return ['disk:{0}'.format(id)]

    def run(self, id, slot):
        disk_info = disk_by_id(self.dispatcher, id)
        disk_status = disk_info.get('status')
        if disk_status:
            data_partition_path = os.path.join('/dev/gptid/', disk_status.get('data_partition_uuid'))
        else:
            raise TaskException(errno.EINVAL, 'Cannot get disk status for: {0}'.format(disk_info['path']))

        try:
            system('/sbin/geli', 'delkey', '-n', str(slot), data_partition_path)
        except SubprocessException as err:
            raise TaskException(errno.EFAULT, 'Cannot delete key of encrypted partition: {0}'.format(err.err))


@private
@accepts(str)
@returns(h.ref('DiskMetadata'))
@description('Creates a backup of GELI metadata')
class DiskGELIBackupMetadataTask(Task):
    @classmethod
    def early_describe(cls):
        return "Backing up metadata of encrypted partition"

    def describe(self, id):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription(
            "Backing up metadata of encrypted partition on {name}",
            name=os.path.basename(disk['path'])
        )

    def verify(self, id):
        disk = disk_by_id(self.dispatcher, id)
        if not disk:
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        return ['disk:{0}'.format(id)]

    def run(self, id):
        disk_info = disk_by_id(self.dispatcher, id)
        disk_status = disk_info.get('status')
        if disk_status:
            data_partition_path = os.path.join('/dev/gptid/', disk_status.get('data_partition_uuid'))
        else:
            raise TaskException(errno.EINVAL, 'Cannot get disk status for: {0}'.format(disk_info['path']))

        with tempfile.NamedTemporaryFile('w+b') as metadata_file:
            try:
                system('/sbin/geli', 'backup', data_partition_path, metadata_file.name)
            except SubprocessException as err:
                raise TaskException(errno.EFAULT, 'Cannot backup metadata of encrypted partition: {0}'.format(err.err))

            metadata_file.seek(0)
            return {'disk': disk_info['path'], 'metadata': base64.b64encode(metadata_file.read()).decode('utf-8')}


@private
@accepts(str, h.ref('DiskMetadata'))
@description('Restores GELI metadata from file')
class DiskGELIRestoreMetadataTask(Task):
    @classmethod
    def early_describe(cls):
        return "Restoring metadata of encrypted partition"

    def describe(self, id, metadata):
        return TaskDescription(
            "Restoring metadata of encrypted partition on {name}",
            name=os.path.basename(metadata.get('disk'))
        )

    def verify(self, id, metadata):
        disk = disk_by_id(self.dispatcher, id)
        if not disk:
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        return ['disk:{0}'.format(id)]

    def run(self, id, metadata):
        disk = metadata.get('disk')
        disk_info = self.dispatcher.call_sync('disk.query', [('path', 'in', disk),
                                                             ('online', '=', True)], {'single': True})
        disk_status = disk_info.get('status')
        if disk_status:
            data_partition_path = os.path.join('/dev/gptid/', disk_status.get('data_partition_uuid'))
        else:
            raise TaskException(errno.EINVAL, 'Cannot get disk status for: {0}'.format(disk))

        with tempfile.NamedTemporaryFile('w+b') as metadata_file:
            metadata_file.write(base64.b64decode(metadata.get('metadata').encode('utf-8')))
            metadata_file.flush()
            try:
                system('/sbin/geli', 'restore', '-f', metadata_file.name, data_partition_path)
            except SubprocessException as err:
                raise TaskException(errno.EFAULT, 'Cannot restore metadata of encrypted partition: {0}'.format(err.err))


@private
@accepts(str, h.ref('DiskAttachParams'))
@description('Attaches GELI encrypted partition')
class DiskGELIAttachTask(Task):
    @classmethod
    def early_describe(cls):
        return "Attaching encrypted partition"

    def describe(self, id, params=None):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Attaching encrypted partition of {name}", name=os.path.basename(disk['path']))

    def verify(self, id, params=None):
        if params is None:
            params = {}
        disk = disk_by_id(self.dispatcher, id)
        if not disk:
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        if not ('key' in params or 'password' in params):
            raise VerifyException(errno.EINVAL, "At least one of key, password have to be specified")

        return ['disk:{0}'.format(id)]

    def run(self, id, params=None):
        if params is None:
            params = {}
        key = base64.b64decode(params.get('key', '') or '')
        password = params.get('password')
        disk_info = disk_by_id(self.dispatcher, id)
        disk_status = disk_info.get('status')
        if disk_status:
            data_partition_path = disk_status.get('data_partition_path')
        else:
            raise TaskException(errno.EINVAL, 'Cannot get disk status for: {0}'.format(disk_info['path']))

        with tempfile.NamedTemporaryFile('wb') as keyfile:
            with tempfile.NamedTemporaryFile('w', encoding='utf-8') as passfile:
                keyfile.write(key)
                keyfile.flush()
                if isinstance(password, Password):
                    passfile.write(password.secret)
                    passfile.flush()
                try:
                    if isinstance(password, Password) and key:
                        system('/sbin/geli', 'attach', '-k', keyfile.name, '-j', passfile.name, data_partition_path)
                    elif key:
                        system('/sbin/geli', 'attach', '-k', keyfile.name, '-p', data_partition_path)
                    else:
                        system('/sbin/geli', 'attach', '-j', passfile.name, data_partition_path)
                    self.dispatcher.call_sync('disk.update_disk_cache', disk_info['path'], timeout=120)
                except SubprocessException as err:
                    logger.warning('Cannot attach encrypted partition: {0}'.format(err.err))


@private
@accepts(str)
@description('Detaches GELI encrypted partition')
class DiskGELIDetachTask(Task):
    @classmethod
    def early_describe(cls):
        return "Detaching encrypted partition"

    def describe(self, id):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Detaching encrypted partition of {name}", name=os.path.basename(disk['path']))

    def verify(self, id):
        disk = disk_by_id(self.dispatcher, id)
        if not disk:
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        return ['disk:{0}'.format(id)]

    def run(self, id):
        disk_info = disk_by_id(self.dispatcher, id)

        disk_status = disk_info.get('status')
        if disk_status:
            data_partition_path = disk_status.get('data_partition_path')
        else:
            raise TaskException(errno.EINVAL, 'Cannot get disk status for: {0}'.format(disk_info['path']))

        try:
            system('/sbin/geli', 'detach', '-f', data_partition_path)
            self.dispatcher.call_sync('disk.update_disk_cache', disk_info['path'], timeout=120)
        except SubprocessException as err:
            logger.warning('Cannot detach encrypted partition: {0}'.format(err.err))


@private
@accepts(str)
@description('Destroys GELI encrypted partition along with GELI metadata')
class DiskGELIKillTask(Task):
    @classmethod
    def early_describe(cls):
        return "Killing encrypted partition"

    def describe(self, id):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription("Killing encrypted partition of {name}", name=os.path.basename(disk['path']))

    def verify(self, id):
        disk = disk_by_id(self.dispatcher, id)
        if not disk:
            raise VerifyException(errno.ENOENT, "Disk {0} not found".format(id))

        return ['disk:{0}'.format(id)]

    def run(self, id):
        disk_info = disk_by_id(self.dispatcher, id)

        disk_status = disk_info.get('status')
        if disk_status:
            data_partition_path = disk_status.get('data_partition_path')
        else:
            raise TaskException(errno.EINVAL, 'Cannot get disk status for: {0}'.format(disk_info['path']))

        try:
            system('/sbin/geli', 'kill', data_partition_path)
            self.dispatcher.call_sync('disk.update_disk_cache', disk_info['path'], timeout=120)
        except SubprocessException as err:
            logger.warning('Cannot kill encrypted partition: {0}'.format(err.err))


@description("Performs SMART test on disk")
@accepts(str, h.ref('DiskSelftestType'))
class DiskTestTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Performing SMART test on disk"

    def describe(self, id, test_type):
        disk = disk_by_id(self.dispatcher, id)
        return TaskDescription(
            "Performing {test_type} SMART test on disk {name}",
            test_type=test_type,
            name=q.get(disk, 'path', '<unknown>')
        )

    def verify(self, id, test_type):
        disk = diskinfo_cache.get(id)
        if not disk:
            raise VerifyException(errno.ENOENT, 'Disk {0} not found'.format(id))
        if not q.get(disk, 'smart_info.smart_enabled'):
            raise VerifyException(
                errno.EINVAL,
                'Disk id: {0}, path: {1} is not S.M.A.R.T enabled'.format(id, disk['path'])
            )
        if not q.get(
            disk, 'smart_info.test_capabilities.{0}'.format(getattr(SelfTestType, test_type).value)
        ):
            raise VerifyException(
                errno.EINVAL,
                'Disk id: {0}, path: {1} does not support {2} S.M.A.R.T test'.format(
                    id, disk['path'], test_type
                )
            )

        return ['disk:{0}'.format(id)]

    def run(self, id, test_type):
        try:
            diskinfo = self.dispatcher.call_sync('disk.get_disk_config_by_id', id)
        except RpcException:
            raise TaskException(errno.ENOENT, 'Disk {0} not found'.format(id))

        def handle_progress(progress):
            self.set_progress(
                progress, "Performing {0} SMART test on disk id: {1}, path: {2}".format(
                    test_type,
                    id,
                    diskinfo['path']
                )
            )

        dev = Device(diskinfo['gdisk_name'])
        dev.run_selftest_and_wait(
            getattr(SelfTestType, test_type).value,
            progress_handler=handle_progress
        )
        handle_progress(100)
        self.dispatcher.call_sync('disk.update_disk_cache', diskinfo['path'], timeout=120)


@description("Performs the given SMART test on the disk IDs specified (in parallel)")
@accepts(h.array(str), h.ref('DiskSelftestType'))
class DiskParallelTestTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Performing parallel SMART test"

    def describe(self, ids, test_type):
        disks = self.dispatcher.call_sync('disk.query', [('id', 'in', ids)])
        return TaskDescription(
            "Performing parallel {test_type} SMART tests on disk: {names}",
            test_type=test_type,
            names=', '.join(q.get(d, 'name', '<unknown>') for d in disks)
        )

    def verify(self, ids, test_type):
        res = []
        for id in ids:
            disk = diskinfo_cache.get(id)
            if not disk:
                raise VerifyException(errno.ENOENT, 'Disk {0} not found'.format(id))

            if not q.get(disk, 'smart_info.smart_enabled'):
                raise VerifyException(
                    errno.EINVAL,
                    'Disk id: {0}, path: {1} is not S.M.A.R.T enabled'.format(id, disk['path'])
                )
            res.append('disk:{0}'.format(id))

        return res

    def run(self, ids, test_type):
        disks = list(self.dispatcher.call_sync('disk.query', [('id', 'in', ids)]))
        progress_dict = {d['name']: 0 for d in disks}
        message = "Performing parallel {0} SMART tests on disks: {1}".format(
            test_type, ', '.join(progress_dict.keys())
        )

        # Set this initial progress message so that none is not displayed even momentarily
        self.set_progress(0, message)

        def progress_report(percentage, disk_name):
            progress_dict[disk_name] = percentage
            self.set_progress(sum(progress_dict.values()) / len(progress_dict), message)

        subtasks = [
            self.run_subtask(
                'disk.test',
                d['id'],
                test_type,
                progress_callback=lambda p, m, e, name=d['name']: progress_report(p, name)
            )
            for d in disks
        ]
        self.join_subtasks(*subtasks)


def get_twcli(controller):
    re_port = re.compile(r'^p(?P<port>\d+).*?\bu(?P<unit>\d+)\b', re.S | re.M)
    output, err = system("/usr/local/sbin/tw_cli", "/c{0}".format(controller), "show")

    units = {}
    for port, unit in re_port.findall(output):
        units[int(unit)] = int(port)

    return units


def device_to_identifier(name, serial=None):
    gdisk = geom.geom_by_name('DISK', name)
    if not gdisk:
        return None

    if serial:
        serial = remove_non_printable(serial).strip()

    if 'lunid' in gdisk.provider.config:
        if serial:
            return "lunid+serial:{0}_{1}".format(gdisk.provider.config['lunid'], serial)

        return "lunid:{0}".format(gdisk.provider.config['lunid'])

    if serial:
        return "serial:{0}".format(serial)

    gpart = geom.geom_by_name('PART', name)
    if gpart:
        for i in gpart.providers:
            if i.config['rawtype'] in ZFS_TYPE_IDS:
                return "uuid:{0}".format(i.config['rawuuid'])

    glabel = geom.geom_by_name('LABEL', name)
    if glabel and glabel.provider:
        return "label:{0}".format(glabel.provider.name)

    return "devicename:{0}".format(os.path.join('/dev', name))


def get_disk_by_path(path):
    for disk in diskinfo_cache.validvalues():
        if disk['path'] == path:
            return disk

        if disk['is_multipath']:
            if path in q.get(disk, 'multipath.members'):
                return disk

    return None


def get_disk_by_lunid_and_serial(lunid, serial):
    return first_or_default(lambda d: d['lunid'] == lunid and d['serial'] == serial, diskinfo_cache.validvalues())


def clean_multipaths(dispatcher):
    dispatcher.threaded(geom.scan)
    cls = geom.class_by_name('MULTIPATH')
    if cls:
        for i in cls.geoms:
            logger.info('Destroying multipath device %s', i.name)
            dispatcher.exec_and_wait_for_event(
                'system.device.detached',
                lambda args: args['path'] == '/dev/multipath/{0}'.format(i.name),
                lambda: system('/sbin/gmultipath', 'destroy', i.name)
            )


def clean_mirrors(dispatcher):
    dispatcher.threaded(geom.scan)
    cls = geom.class_by_name('MIRROR')
    if cls:
        for i in cls.geoms:
            if i.name.endswith('.sync'):
                continue

            logger.info('Destroying mirror device %s', i.name)
            dispatcher.exec_and_wait_for_event(
                'system.device.detached',
                lambda args: args['path'] == '/dev/mirror/{0}'.format(i.name),
                lambda: system('/sbin/gmirror', 'destroy', i.name)
            )


def get_multipath_name():
    for i in ('/dev/multipath/mpath{0}'.format(n) for n in range(0, 1000)):
        if os.path.exists(i):
            continue

        if get_disk_by_path(i):
            continue

        return os.path.basename(i)


def attach_to_multipath(dispatcher, disk, ds_disk, path):
    if not disk and ds_disk:
        logger.info("Device node %s <%s> is marked as multipath, creating single-node multipath", path, ds_disk['serial'])
        nodename = os.path.basename(ds_disk['path'])
        logger.info('Reusing %s path', nodename)

        # Degenerated single-disk multipath
        try:
            dispatcher.exec_and_wait_for_event(
                'system.device.attached',
                lambda args: args['path'] == '/dev/multipath/{0}'.format(nodename),
                lambda: system('/sbin/gmultipath', 'create', nodename, path)
            )
        except SubprocessException as e:
            logger.warning('Cannot create multipath: {0}'.format(e.err))
            return

        ret = {
            'is_multipath': True,
            'path': os.path.join('/dev/multipath', nodename),
        }
    elif disk:
        logger.info("Device node %s is another path to disk <%s> (%s)", path, disk['id'], disk['description'])
        if disk['is_multipath']:
            if path in q.get(disk, 'multipath.members'):
                # Already added
                return

            # Attach new disk
            try:
                system('/sbin/gmultipath', 'add', q.get(disk, 'multipath.node'), path)
            except SubprocessException as e:
                logger.warning('Cannot attach {0} to multipath: {0}'.format(path, e.err))
                return

            nodename = q.get(disk, 'multipath.node')
            ret = {
                'is_multipath': True,
                'path': os.path.join('/dev/multipath', q.get(disk, 'multipath.node')),
            }
        else:
            # Create new multipath
            logger.info('Creating new multipath device')

            # If disk was previously tied to specific cdev path (/dev/multipath[0-9]+)
            # reuse that path. Otherwise pick up first multipath device name available
            if ds_disk and ds_disk['is_multipath']:
                nodename = os.path.basename(ds_disk['path'])
                logger.info('Reusing %s path', nodename)
            else:
                nodename = get_multipath_name()
                logger.info('Using new %s path', nodename)

            try:
                dispatcher.exec_and_wait_for_event(
                    'system.device.attached',
                    lambda args: args['path'] == '/dev/multipath/{0}'.format(nodename),
                    lambda: system('/sbin/gmultipath', 'create', nodename, disk['path'], path)
                )
            except SubprocessException as e:
                logger.warning('Cannot create multipath: {0}'.format(e.err))
                return

            ret = {
                'is_multipath': True,
                'path': os.path.join('/dev/multipath', nodename),
            }

    # Force re-taste
    with open(os.path.join('/dev/multipath', nodename), 'rb+') as f:
        pass

    dispatcher.threaded(geom.scan)
    gmultipath = geom.geom_by_name('MULTIPATH', nodename)
    ret['multipath'] = generate_multipath_info(gmultipath)
    return ret


def disk_by_id(dispatcher, id):
    return dispatcher.call_sync('disk.query', [('id', '=', id)], {'single': True})


def generate_partitions_list(gpart):
    if not gpart:
        return

    for p in gpart.providers:
        paths = [os.path.join("/dev", p.name)]
        if not p.config:
            continue

        label = p.config.get('label')
        uuid = p.config.get('rawuuid')
        eli = geom.geom_by_name('ELI', 'gptid/{0}.eli'.format(uuid))

        if label:
            paths.append(os.path.join("/dev/gpt", label))

        if uuid:
            if eli:
                elipath = uuid + '.eli'
                paths.append(os.path.join("/dev/gptid", elipath))
            else:
                paths.append(os.path.join("/dev/gptid", uuid))

        yield {
            'name': p.name,
            'paths': paths,
            'mediasize': int(p.mediasize),
            'uuid': uuid,
            'type': p.config['type'],
            'rawtype': p.config['rawtype'],
            'label': p.config.get('label'),
            'encrypted': True if eli else False
        }


def generate_multipath_info(gmultipath):
    return {
        'status': gmultipath.config['State'],
        'mode': gmultipath.config['Mode'],
        'uuid': gmultipath.config['UUID'],
        'node': gmultipath.name,
        'members': {os.path.join('/dev', c.provider.name): c.config['State'] for c in gmultipath.consumers}
    }


def update_disk_cache(dispatcher, path):
    dispatcher.threaded(geom.scan)
    name = re.match('/dev/(.*)', path).group(1)
    gdisk = geom.geom_by_name('DISK', name)
    gpart = geom.geom_by_name('PART', name)
    gmultipath = None

    # Handle diskid labels
    if gpart is None:
        glabel = geom.geom_by_name('LABEL', name)
        if glabel and glabel.provider and glabel.provider.name.startswith('diskid/'):
            gpart = geom.geom_by_name('PART', glabel.provider.name)

    if name.startswith('multipath/'):
        multipath_name = re.match('multipath/(.*)', name).group(1)
        gmultipath = geom.geom_by_name('MULTIPATH', multipath_name)

    disk = get_disk_by_path(path)
    if not disk:
        return

    old_id = disk['id']

    if gmultipath:
        # Path represents multipath device (not disk device)
        # MEDIACHANGE event -> use first member for hardware queries
        cons = next(gmultipath.consumers)
        gdisk = cons.provider.geom

    if not gdisk:
        return

    try:
        camdev = CamDevice(gdisk.name)
    except RuntimeError:
        camdev = None

    provider = gdisk.provider
    partitions = list(generate_partitions_list(gpart))
    identifier = device_to_identifier(gdisk.name, camdev.serial if camdev else provider.config.get('ident'))
    data_part = first_or_default(lambda x: x['rawtype'] in ZFS_TYPE_IDS, partitions)
    data_uuid = data_part["uuid"] if data_part else None
    data_path = data_uuid

    encrypted = False
    if data_part and data_part["encrypted"]:
        data_path = data_uuid + '.eli'
        encrypted = True

    swap_part = first_or_default(lambda x: x['type'] == 'freebsd-swap', partitions)
    swap_uuid = swap_part["uuid"] if swap_part else None

    # Get enclosure information
    enclosure = None
    enclosures = dispatcher.call_sync('disk.enclosure.query')
    for i in enclosures:
        if list(filter(lambda d: d['disk_name'] == path, i['devices'])):
            enclosure = i['id']

    disk.update({
        'mediasize': provider.mediasize,
        'sectorsize': provider.sectorsize,
        'id': identifier,
        'schema': gpart.config.get('scheme') if gpart else None,
        'empty': len(partitions) == 0,
        'partitions': partitions,
        'data_partition_uuid': data_uuid,
        'data_partition_path': os.path.join("/dev/gptid", data_path) if data_uuid else None,
        'swap_partition_uuid': swap_uuid,
        'swap_partition_path': os.path.join("/dev/gptid", swap_uuid) if swap_uuid else None,
        'encrypted': encrypted,
        'gdisk_name': gdisk.name,
        'enclosure': enclosure
    })

    # Get S.M.A.R.T information
    update_smart_info(dispatcher, disk)

    if gmultipath:
        disk['multipath'] = generate_multipath_info(gmultipath)

    # Purge old cache entry if identifier has changed
    if old_id != identifier:
        logger.debug('Removing disk cache entry for <%s> because identifier changed', old_id)
        diskinfo_cache.remove(old_id)
        diskinfo_cache.put(identifier, disk)
        dispatcher.datastore.delete('disks', old_id)
        dispatcher.dispatch_event('disk.changed', {
            'operation': 'delete',
            'ids': [old_id]
        })

        if disk['enclosure']:
            dispatcher.dispatch_event('disk.enclosure.changed', {
                'operation': 'update',
                'ids': disk['enclosure']
            })

    persist_disk(dispatcher, disk)
    # post this persist disk check to see if the 'smart' value in the databse
    # (enabled or disabled) matches the actual disk's smart_enabled value and
    # if not then make it so
    ds_disk = dispatcher.datastore.get_by_id('disks', disk['id'])
    if ds_disk['smart'] != disk['smart_info']['smart_enabled']:
        device_smart_handle = Device(disk['gdisk_name'])
        toggle_result = device_smart_handle.smart_toggle('on' if ds_disk['smart'] else 'off')
        if not toggle_result[0]:
            logger.debug(
                "Tried to toggle {0}".format(path) +
                " SMART enabled to: {0} and failed with error: {1}".format(
                    ds_disk['smart'],
                    toggle_result[1]
                )
            )


def generate_disk_cache(dispatcher, path):
    dispatcher.threaded(geom.scan)
    name = os.path.basename(path)
    gdisk = geom.geom_by_name('DISK', name)
    multipath_info = None
    max_rotation = None

    try:
        camdev = CamDevice(gdisk.name)
    except RuntimeError:
        camdev = None

    provider = gdisk.provider
    serial = camdev.serial if camdev else provider.config.get('ident')
    identifier = device_to_identifier(name, serial)
    ds_disk = dispatcher.datastore.get_by_id('disks', identifier)

    try:
        camdev = dispatcher.threaded(CamDevice, gdisk.name)
    except RuntimeError:
        camdev = None

    try:
        max_rotation = int(provider.config.get('rotationrate', 0))
    except:
        pass

    with dispatcher.get_lock('multipath'):
        # Path repesents disk device (not multipath device) and has NAA ID attached
        lunid = gdisk.provider.config.get('lunid')
        if lunid:
            # Check if device could be part of multipath configuration
            d = get_disk_by_lunid_and_serial(lunid, serial)
            if (d and d['path'] != path) or (ds_disk and ds_disk['is_multipath']):
                multipath_info = attach_to_multipath(dispatcher, d, ds_disk, path)

        disk = {
            'path': path,
            'is_multipath': False,
            'description': provider.config['descr'],
            'serial': serial,
            'max_rotation': max_rotation,
            'is_ssd': max_rotation == 0,
            'lunid': provider.config.get('lunid'),
            'id': identifier,
            'controller': camdev.__getstate__() if camdev else None,
        }

        if multipath_info:
            disk.update(multipath_info)
            path = multipath_info['path']

        diskinfo_cache.put(identifier, disk)

    update_disk_cache(dispatcher, path)
    configure_disk(dispatcher.datastore, identifier)

    logger.info('Added <%s> (%s) to disk cache', identifier, disk['description'])


def purge_disk_cache(dispatcher, path):
    dispatcher.threaded(geom.scan)
    delete = False
    disk = get_disk_by_path(path)

    if not disk:
        return

    if disk['is_multipath']:
        # Looks like one path was removed
        logger.info('Path %s to disk <%s> (%s) was removed', path, disk['id'], disk['description'])
        q.get(disk, 'multipath.members').pop(path, None)

        # Was this last path?
        if len(q.get(disk, 'multipath.members')) == 0:
            logger.info('Disk %s <%s> (%s) was removed (last path is gone)', path, disk['id'], disk['description'])
            diskinfo_cache.remove(disk['id'])
            delete = True
        else:
            diskinfo_cache.put(disk['id'], disk)

    else:
        logger.info('Disk %s <%s> (%s) was removed', path, disk['id'], disk['description'])
        diskinfo_cache.remove(disk['id'])
        delete = True

    if delete:
        # Mark disk for auto-delete
        ds_disk = dispatcher.datastore.get_by_id('disks', disk['id'])
        ds_disk['delete_at'] = datetime.utcnow() + EXPIRE_TIMEOUT
        dispatcher.datastore.update('disks', ds_disk['id'], ds_disk)

    dispatcher.dispatch_event('disk.changed', {
        'operation': 'update',
        'ids': [disk['id']]
    })

    if disk['enclosure']:
        dispatcher.dispatch_event('disk.enclosure.changed', {
            'operation': 'update',
            'ids': disk['enclosure']
        })


def persist_disk(dispatcher, disk):
    ds_disk = dispatcher.datastore.get_by_id('disks', disk['id'])
    new = ds_disk is None
    ds_disk = ds_disk or {}
    ds_disk.update({
        'lunid': disk['lunid'],
        'path': disk['path'],
        'name': os.path.basename(disk['path']),
        'mediasize': disk['mediasize'],
        'serial': disk['serial'],
        'is_multipath': disk['is_multipath'],
        'delete_at': None
    })

    if 'standby_mode' not in ds_disk:
        ds_disk.update({'standby_mode': 0})

    if 'apm_mode' not in ds_disk:
        ds_disk.update({'apm_mode': 0})

    if 'acoustic_level' not in ds_disk:
        ds_disk.update({'acoustic_level': 'DISABLED'})

    if 'smart' not in ds_disk:
        ds_disk.update({'smart': True if disk['smart_info']['smart_capable'] else False})

    dispatcher.datastore.upsert('disks', disk['id'], ds_disk)
    dispatcher.dispatch_event('disk.changed', {
        'operation': 'create' if new else 'update',
        'ids': [disk['id']]
    })

    if disk['enclosure']:
        dispatcher.dispatch_event('disk.enclosure.changed', {
            'operation': 'update',
            'ids': disk['enclosure']
        })


def configure_disk(datastore, id):
    disk = datastore.get_by_id('disks', id)
    acc_level = getattr(AcousticLevel, disk.get('acoustic_level', 'DISABLED')).value
    powermgmt = disk.get('apm_mode', 0)

    if not disk['path'].startswith('/dev/ada'):
        return

    try:
        system('/usr/local/sbin/ataidle', '-P', str(powermgmt), '-A', str(acc_level), disk['path'])
    except SubprocessException as err:
        logger.warning('Cannot configure power management for disk {0}: {1}'.format(id, err.err))

    if disk.get('standby_mode'):
        def configure_standby(mode):
            try:
                system(
                    '/usr/local/sbin/ataidle',
                    '-I',
                    mode,
                    disk['path']
                )
            except SubprocessException as err:
                logger.warning('Cannot configure standby mode for disk {0}: {1}', id, err.err)

        standby_mode = str(disk['standby_mode'])
        gevent.spawn_later(60, configure_standby, standby_mode)


def update_smart_info(dispatcher, disk):
    updated = False
    # setting all_info to False below makes pySMART skip over fields we already
    # have in the disk dict (like name, path, serial number, is_ssd, max_roation and so on)
    smart_info = Device(disk['gdisk_name']).__getstate__(all_info=False)
    disk_name = disk['gdisk_name']
    smart_status = smart_info['smart_status']

    if disk.get('smart_info') != smart_info:
        disk['smart_info'] = smart_info
        diskinfo_cache.update_one(disk['id'], smart_info=smart_info)
        updated = True

    existing_smart_alerts = dispatcher.call_sync(
        'alert.query',
        [
            ('active', '=', True),
            ('dismissed', '=', False),
            ('clazz', 'in', ('SmartFail', 'SmartWarn')),
            ('target', '=', disk_name)
        ]
    )

    if smart_status in ('FAIL', 'WARN'):
        # We need to issue a S.M.A.R.T alert for this disk
        alert_class, title = SMART_ALERT_MAP[smart_status]
        alert_payload = {
            'clazz': alert_class,
            'title': title,
            'target': disk_name,
            'description': 'Disk {0} S.M.A.R.T status: {1}.\
            See disk info in GUI/CLI for details'.format(disk_name, smart_status)
        }

        alert_exists = False

        for smart_alert in existing_smart_alerts:
            if smart_alert['clazz'] == alert_class and smart_alert['target'] == disk_name:
                alert_exists = True
                continue
            dispatcher.call_sync('alert.cancel', smart_alert['id'])

        if not alert_exists:
            dispatcher.call_sync('alert.emit', alert_payload)
    elif smart_status == 'PASS':
        # for various reasons the SMART status of this disk (or a disk with this name)
        # may have a previous 'FAIL' | 'WARN' smart status in which case clear those alerts
        for smart_alert in existing_smart_alerts:
            dispatcher.call_sync('alert.cancel', smart_alert['id'])

    return updated


def collect_debug(dispatcher):
    yield AttachCommandOutput('gpart', ['/sbin/gpart', 'show'])
    yield AttachData('disk-cache-state', json.dumps(diskinfo_cache.query(), indent=4))
    yield AttachData('confxml', ElementTree.tostring(confxml(), encoding='utf8', method='xml'))


def _depends():
    return ['AlertPlugin', 'DevdPlugin']


def _init(dispatcher, plugin):
    def on_device_attached(args):
        path = args['path']
        if re.match(r'^/dev/(da|ada|vtbd|mfid|nvd)[0-9]+$', path):
            # Regenerate disk cache
            logger.info("New disk attached: {0}".format(path))
            with dispatcher.get_lock('diskcache:{0}'.format(path)):
                generate_disk_cache(dispatcher, path)

            disk = get_disk_by_path(path)
            dispatcher.emit_event('disk.attached', {
                'path': disk['path'],
                'id': disk['id']
            })

    def on_device_detached(args):
        path = args['path']
        if re.match(r'^/dev/(da|ada|vtbd|nvd|mfid)[0-9]+$', path):
            logger.info("Disk %s detached", path)
            disk = get_disk_by_path(path)
            purge_disk_cache(dispatcher, path)

            if disk:
                dispatcher.emit_event('disk.detached', {
                    'path': path,
                    'id': disk['id']
                })

    def on_device_mediachange(args):
        # Regenerate caches
        path = args['path']
        if re.match(r'^/dev/(da|ada|vtbd|nvd|mfid|multipath/mpath)[0-9]+$', path):
            with dispatcher.get_lock('diskcache:{0}'.format(path)):
                logger.info('Updating disk cache for device %s', args['path'])
                update_disk_cache(dispatcher, args['path'])

    def smart_updater():
        while True:
            updated_disks = [
                disk['id'] for disk in diskinfo_cache.validvalues() if update_smart_info(dispatcher, disk)
            ]
            if updated_disks:
                dispatcher.dispatch_event(
                    'disk.changed',
                    {
                        'operation': 'update',
                        'ids': updated_disks
                    }
                )
            gevent.sleep(SMART_CHECK_INTERVAL)

    plugin.register_schema_definition('Disk', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'rname': {'type': 'string'},
            'path': {'type': 'string'},
            'serial': {'type': ['string', 'null']},
            'mediasize': {'type': 'integer'},
            'smart': {'type': 'boolean'},
            'standby_mode': {'type': ['integer', 'null']},
            'apm_mode': {'type': ['integer', 'null']},
            'acoustic_level': {'$ref': 'DiskAcousticlevel'},
            'status': {'$ref': 'DiskStatus'},
            'is_multipath': {'type': 'boolean'}
        }
    })

    plugin.register_schema_definition('DiskAcousticlevel', {
        'type': 'string',
        'enum': ['DISABLED', 'MINIMUM', 'MEDIUM', 'MAXIMUM']
    })

    plugin.register_schema_definition('DiskStatus', {
        'type': 'object',
        'properties': {
            'mediasize': {'type': 'integer'},
            'sectorsize': {'type': 'integer'},
            'description': {'type': 'string'},
            'serial': {'type': ['string', 'null']},
            'lunid': {'type': 'string'},
            'max_rotation': {'type': ['integer', 'null']},
            'is_ssd': {'type': 'boolean'},
            'is_multipath': {'type': 'boolean'},
            'is_encrypted': {'type': 'boolean'},
            'id': {'type': 'string'},
            'schema': {'type': ['string', 'null']},
            'controller': {'type': 'object'},
            'empty': {'type': 'boolean'},
            'partitions': {
                'type': 'array',
                'items': {'$ref': 'DiskPartition'}
            },
            'multipath': {
                'type': 'object',
                'properties': {
                    'status': {'type': 'string'},
                    'node': {'type': 'string'},
                    'members': {
                        'type': 'object',
                        'items': {'type': 'string'},
                    },
                }
            },
            'data_partition_uuid': {'type': 'string'},
            'data_partition_path': {'type': 'string'},
            'swap_partition_uuid': {'type': 'string'},
            'swap_partition_path': {'type': 'string'},
            'encrypted': {'type': 'boolean'},
            'gdisk_name': {'type': 'string'},
            'enclosure': {'type': ['string', 'null']},
            'smart_info': {'$ref': 'SmartInfo'},
        }
    })

    plugin.register_schema_definition('DiskPartition', {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'paths': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'mediasize': {'type': 'integer'},
            'uuid': {'type': 'string'},
            'type': {'type': 'string'},
            'label': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('DiskEraseMethod', {
        'type': 'string',
        'enum': ['QUICK', 'ZEROS', 'RANDOM']
    })

    plugin.register_schema_definition('DiskSelftestType', {
        'type': 'string',
        'enum': list(SelfTestType.__members__.keys())
    })

    plugin.register_schema_definition('DiskAttachParams', {
        'type': 'object',
        'properties': {
            'key': {'type': 'string'},
            'password': {'type': 'password'}
        }
    })

    plugin.register_schema_definition('DiskSetKeyParams', {
        'type': 'object',
        'properties': {
            'key': {'type': 'string'},
            'password': {'type': 'password'},
            'slot': {'type': 'integer'}
        }
    })

    plugin.register_schema_definition('DiskMetadata', {
        'type': 'object',
        'properties': {
            'disk': {'type': 'string'},
            'metadata': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('EnclosureStatus', {
        'type': 'string',
        'enum': list(EnclosureStatus.__members__.keys())
    })

    plugin.register_schema_definition('EnclosureElementStatus', {
        'type': 'string',
        'enum': list(ElementStatus.__members__.keys()) + ['UNKNOWN']
    })

    plugin.register_schema_definition('Enclosure', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'description': {'type': 'string'},
            'status': {
                'type': 'array',
                'items': {'$ref': 'EnclosureStatus'},
            },
            'devices': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'index': {'type': 'integer'},
                        'status': {'$ref': 'EnclosureElementStatus'},
                        'name': {'type': 'string'},
                        'disk_name': {'type': 'string'}
                    }
                }
            }
        }
    })

    plugin.register_schema_definition('SmartInfo', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'interface': {'type': ['string', 'null']},
            'model': {'type': ['string', 'null']},
            'smart_capable': {'type': 'boolean'},
            'smart_enabled': {'type': 'boolean'},
            'smart_status': {'type': ['string', 'null']},
            'firmware': {'type': ['string', 'null']},
            'messages': h.array(str),
            'test_capabilities': {'$ref': 'SupportedSmartTests'},
            'tests': {
                'oneOf': [
                    {
                        'type': 'array',
                        'items': {'$ref': 'SmartTestResult'},
                    },
                    {'type': 'null'}
                ]
            },
            'diagnostics': h.object(),
            'temperature': {'type': 'integer'},
            'attributes': {
                'type': 'array',
                'items': {'oneOf': [{'$ref': 'SmartAttribute'}, {'type': 'null'}]},
                'minItems': 255,
                'maxItems': 255
            }
        }
    })

    plugin.register_schema_definition('SmartTestResult', {
        'type': 'object',
        'additonalProperties': False,
        'properties': {
            'num': {'type': ['integer', 'null']},
            'type': {'type': 'string'},
            'status': {'type': 'string'},
            'hours': {'type': 'string'},
            'lba': {'type': 'string'},
            'remain': {'type': 'string'},
            'segment': {'type': ['string', 'null']},
            'sense': {'type': ['string', 'null']},
            'asc': {'type': ['string', 'null']},
            'ascq': {'type': ['string', 'null']}
        }
    })

    plugin.register_schema_definition('SupportedSmartTests', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'offline': {'type': 'boolean'},
            'short': {'type': 'boolean'},
            'long': {'type': 'boolean'},
            'conveyance': {'type': 'boolean'},
            'selective': {'type': 'boolean'}
        }
    })

    plugin.register_schema_definition('SmartAttribute', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'num': {
                'type': 'integer',
                'minimum': 1,
                'maximum': 255
            },
            'flags': {'type': 'string'},
            'raw': {'type': 'string'},
            'value': {'type': 'string'},
            'worst': {'type': 'string'},
            'threshold': {'type': 'string'},
            'type': {'type': 'string'},
            'updated': {'type': 'string'},
            'when_failed': {'type': 'string'},
        }
    })

    plugin.register_provider('disk', DiskProvider)
    plugin.register_provider('disk.enclosure', EnclosureProvider)
    plugin.register_event_handler('system.device.attached', on_device_attached)
    plugin.register_event_handler('system.device.detached', on_device_detached)
    plugin.register_event_handler('system.device.mediachange', on_device_mediachange)
    plugin.register_task_handler('disk.erase', DiskEraseTask)
    plugin.register_task_handler('disk.format.gpt', DiskGPTFormatTask)
    plugin.register_task_handler('disk.format.boot', DiskBootFormatTask)
    plugin.register_task_handler('disk.geli.init', DiskGELIInitTask)
    plugin.register_task_handler('disk.geli.ukey.set', DiskGELISetUserKeyTask)
    plugin.register_task_handler('disk.geli.ukey.del', DiskGELIDelUserKeyTask)
    plugin.register_task_handler('disk.geli.mkey.backup', DiskGELIBackupMetadataTask)
    plugin.register_task_handler('disk.geli.mkey.restore', DiskGELIRestoreMetadataTask)
    plugin.register_task_handler('disk.geli.attach', DiskGELIAttachTask)
    plugin.register_task_handler('disk.geli.detach', DiskGELIDetachTask)
    plugin.register_task_handler('disk.geli.kill', DiskGELIKillTask)
    plugin.register_task_handler('disk.install_bootloader', DiskInstallBootloaderTask)
    plugin.register_task_handler('disk.update', DiskConfigureTask)
    plugin.register_task_handler('disk.delete', DiskDeleteTask)
    plugin.register_task_handler('disk.test', DiskTestTask)
    plugin.register_task_handler('disk.parallel_test', DiskParallelTestTask)

    plugin.register_event_type('disk.changed')
    plugin.register_event_type('disk.attached')
    plugin.register_event_type('disk.detached')
    plugin.register_event_type('disk.enclosure.changed')

    plugin.register_debug_hook(collect_debug)

    # Start with marking all disks as unavailable
    for i in dispatcher.datastore.query_stream('disks'):
        if not i.get('delete_at'):
            i['delete_at'] = datetime.utcnow() + EXPIRE_TIMEOUT

        dispatcher.datastore.update('disks', i['id'], i)

    # Destroy all swap devices and mirrors
    for dev in getswapinfo():
        system('/sbin/swapoff', os.path.join('/dev', dev.devname))

    clean_mirrors(dispatcher)

    # Destroy all existing multipaths
    clean_multipaths(dispatcher)

    # Generate cache for all disks
    greenlets = []
    disk_cache_start = time.time()
    for i in dispatcher.rpc.call_sync('system.device.get_devices', 'disk'):
        greenlets.append(gevent.spawn(on_device_attached, {'path': i['path']}))

    gevent.wait(greenlets)
    logger.info("Syncing disk cache took {0:.0f} ms".format((time.time() - disk_cache_start) * 1000))

    gevent.spawn(smart_updater)
    dispatcher.track_resources(
        'disk.query',
        'entity-subscriber.disk.changed',
        lambda id: f'disk:{id}',
        lambda volume: ['root']
    )
