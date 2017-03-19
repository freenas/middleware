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

import errno
import ssl
import uuid
import logging
import re
from datetime import datetime
from pyVim import connect, task
from pyVmomi import vim, vmodl
from mako.template import Template
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, generator, accepts, returns, description
from freenas.utils import normalize, query as q
from freenas.utils.password import unpassword
from task import Provider, Task, TaskDescription, TaskException, ProgressTask, query


logger = logging.getLogger(__name__)
ALERT_TEMPLATE = """
Following VMware snapshot operations failed during creation of snapshot ${id}:
% for i in failed_snapshots:
% if i["when"] == "create":
- Creating snapshot of virtual machine ${i["vm"]} on datastore ${i["datastore"]}: ${i["error"]}
% elif i["when"] == "delete":
- Deleting snapshot of virtual machine ${i["vm"]} on datastore ${i["datastore"]}: ${i["error"]}
% elif i["when"] == "connect":
- Connecting to VMware host at ${i["host"]}: ${i["error"]}
% endif
% endfor
"""


class VMwareProvider(Provider):
    @generator
    @accepts(str, str, str, bool)
    @returns(h.ref('VmwareDatastore'))
    def get_datastores(self, address, username, password, full=False):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ssl_context.verify_mode = ssl.CERT_NONE

        try:
            si = connect.SmartConnect(host=address, user=username, pwd=password, sslContext=ssl_context)
            content = si.RetrieveContent()
            vm_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        except vmodl.MethodFault as err:
            raise RpcException(errno.EFAULT, err.msg)

        try:
            for datastore in content.viewManager.CreateContainerView(content.rootFolder, [vim.Datastore], True).view:
                vms = []
                if full:
                    for vm in vm_view.view:
                        if datastore not in vm.datastore:
                            continue

                        vms.append({
                            'id': vm.config.uuid,
                            'name': vm.summary.config.name,
                            'on': vm.summary.runtime.powerState == 'poweredOn',
                            'snapshottable': can_be_snapshotted(vm)
                        })

                yield {
                    'id': datastore.info.url,
                    'name': datastore.info.name,
                    'free_space': datastore.info.freeSpace,
                    'virtual_machines': vms
                }
        finally:
            connect.Disconnect(si)


class VMwareDatasetsProvider(Provider):
    @generator
    @query('VmwareDataset')
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('vmware.datasets', *(filter or []), **(params or {}))


@accepts(h.all_of(
    h.ref('VmwareDataset'),
    h.required('name', 'dataset', 'datastore', 'peer')
))
class VMWareDatasetCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating VMware dataset mapping"

    def describe(self, dataset):
        return TaskDescription("Creating VMware datastore mapping for {name}", name=dataset['datastore'])

    def verify(self, dataset):
        return ['system']

    def run(self, dataset):
        normalize(dataset, {
            'vm_filter_op': 'NONE',
            'vm_filter_entries': []
        })

        first = self.datastore.query('vmware.datasets', count=True) == 0
        id = self.datastore.insert('vmware.datasets', dataset)

        if first:
            # To not waste cycles, we register snapshot pre- and post-creation hooks only if there's at
            # least one VMware dataset mapping
            self.dispatcher.register_task_hook('volume.snapshot.create:before', 'vmware.snapshot.take')
            self.dispatcher.register_task_hook('volume.snapshot.create:after', 'vmware.snapshot.clean')
            self.dispatcher.register_task_hook('volume.snapshot.create:error', 'vmware.snapshot.clean')

        self.dispatcher.emit_event('vmware.dataset.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


class VMWareDatasetUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating VMware dataset mapping"

    def describe(self, id, updated_fields):
        pass

    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        dataset = self.datastore.get_by_id('vmware.datasets', id)
        if not dataset:
            raise TaskException(errno.ENOENT, 'VMware dataset mapping {0} not found'.format(id))

        dataset.update(updated_fields)
        self.datastore.update('vmware.datasets', id, dataset)
        self.dispatcher.emit_event('vmware.dataset.changed', {
            'operation': 'update',
            'ids': [id]
        })


class VMWareDatasetDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Removing VMware dataset mapping"

    def describe(self, id):
        dataset = self.datastore.get_by_id('vmware.datasets', id)
        return TaskDescription("Removing VMware dataset mapping {name}".format(name=q.get(dataset, 'name')))

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.get_by_id('vmware.datasets', id):
            raise TaskException(errno.ENOENT, 'VMware dataset mapping {0} not found'.format(id))

        self.datastore.delete('vmware.datasets', id)

        if self.datastore.query('vmware.datasets', count=True) == 0:
            # Unregister hooks once we remove the last mapping
            self.dispatcher.unregister_task_hook('volume.snapshot.create:before', 'vmware.snapshot.take')
            self.dispatcher.unregister_task_hook('volume.snapshot.create:after', 'vmware.snapshot.clean')
            self.dispatcher.unregister_task_hook('volume.snapshot.create:error', 'vmware.snapshot.clean')

        self.dispatcher.emit_event('vmware.dataset.changed', {
            'operation': 'delete',
            'ids': [id]
        })


class CreateVMSnapshotsTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Creating VMware snapshots"

    def describe(self, snapshot, recursive=False):
        return TaskDescription("Creating VMware snapshots")

    def verify(self, snapshot, recursive=False):
        return []

    def run(self,  snapshot, recursive=False):
        # Find the matching datastore mappings
        dataset = snapshot.get('dataset') or snapshot.get('id').split('@')[0]
        vm_snapname = 'FreeNAS-{0}'.format(str(uuid.uuid4()))
        vm_snapdescr = '{0} (Created by FreeNAS)'.format(datetime.utcnow())
        failed_snapshots = []

        # Save the snapshot name in parent task environment to the delete counterpart can find it
        self.dispatcher.task_setenv(self.environment['parent'], 'vmware_snapshot_name', vm_snapname)

        for mapping in self.datastore.query_stream('vmware.datasets'):
            if recursive:
                if not re.search('^{0}(/|$)'.format(mapping['dataset']), dataset) and \
                   not re.search('^{0}(/|$)'.format(dataset), mapping['dataset']):
                    continue
            else:
                if mapping['dataset'] != dataset:
                    continue

            peer = self.dispatcher.call_sync('peer.query', [('id', '=', mapping['peer'])], {'single': True})
            if not peer:
                failed_snapshots.append({
                    'when': 'connect',
                    'host': '<mapping {0}>'.format(mapping['name']),
                    'datastore': mapping['datastore'],
                    'error': 'Cannot find peer entry for mapping {0}'.format(mapping['name'])
                })
                continue

            try:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                ssl_context.verify_mode = ssl.CERT_NONE
                si = connect.SmartConnect(
                    host=q.get(peer, 'credentials.address'),
                    user=q.get(peer, 'credentials.username'),
                    pwd=unpassword(q.get(peer, 'credentials.password')),
                    sslContext=ssl_context
                )
                content = si.RetrieveContent()
                vm_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
            except BaseException as err:
                logger.warning('Connecting to VMware instance at {0} failed: {1}'.format(
                    q.get(peer, 'credentials.address'),
                    str(err)
                ))

                failed_snapshots.append({
                    'when': 'connect',
                    'host': q.get(peer, 'credentials.address'),
                    'datastore': mapping['datastore'],
                    'error': getattr(err, 'msg') or str(err)
                })

                continue

            for vm in vm_view.view:
                if mapping['vm_filter_op'] == 'INCLUDE' and vm.summary.config.name not in mapping['vm_filter_entries']:
                    continue

                if mapping['vm_filter_op'] == 'EXCLUDE' and vm.summary.config.name in mapping['vm_filter_entries']:
                    continue

                if not any(i.info.name == mapping['datastore'] for i in vm.datastore):
                    continue

                if vm.snapshot and find_snapshot(vm.snapshot.rootSnapshotList, vm_snapname):
                    continue

                logger.info('Creating snapshot of VM {0} (datastore {1})'.format(
                    vm.summary.config.name,
                    mapping['datastore'])
                )

                try:
                    task.WaitForTask(vm.CreateSnapshot_Task(
                        name=vm_snapname, description=vm_snapdescr,
                        memory=False, quiesce=False
                    ))
                except vmodl.MethodFault as err:
                    logger.warning('Creating snapshot of {0} failed: {1}'.format(vm.summary.config.name, err.msg))
                    failed_snapshots.append({
                        'when': 'create',
                        'vm': vm.summary.config.name,
                        'datastore': mapping['datastore'],
                        'error': err.msg
                    })

            connect.Disconnect(si)

        self.dispatcher.task_setenv(self.environment['parent'], 'vmware_failed_snapshots', failed_snapshots)


class DeleteVMSnapshotsTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Removing VMware snapshots"

    def describe(self, snapshot, recursive=False):
        return TaskDescription("Removing VMware snapshots")

    def verify(self, snapshot, recursive=False):
        return []

    def run(self, snapshot, recursive=False):
        dataset = snapshot.get('dataset') or snapshot.get('id').split('@')[0]
        id = snapshot.get('id') or '{0}@{1}'.format(dataset, snapshot.get('name'))
        vm_snapname = self.environment.get('vmware_snapshot_name')
        failed_snapshots = self.environment.get('vmware_failed_snapshots', [])

        if not vm_snapname:
            return

        logger.info('VM snapshot name is: {0}'.format(vm_snapname))

        for mapping in self.datastore.query_stream('vmware.datasets'):
            if recursive:
                if not re.search('^{0}(/|$)'.format(mapping['dataset']), dataset) and \
                   not re.search('^{0}(/|$)'.format(dataset), mapping['dataset']):
                    continue
            else:
                if mapping['dataset'] != dataset:
                    continue

            peer = self.dispatcher.call_sync('peer.query', [('id', '=', mapping['peer'])], {'single': True})
            if not peer:
                failed_snapshots.append({
                    'when': 'connect',
                    'host': '<mapping {0}>'.format(mapping['name']),
                    'datastore': mapping['datastore'],
                    'error': 'Cannot find peer entry for mapping {0}'.format(mapping['name'])
                })
                continue

            if any(i.get('host') == q.get(peer, 'credentials.address') for i in failed_snapshots):
                continue

            try:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                ssl_context.verify_mode = ssl.CERT_NONE
                si = connect.SmartConnect(
                    host=q.get(peer, 'credentials.address'),
                    user=q.get(peer, 'credentials.username'),
                    pwd=unpassword(q.get(peer, 'credentials.password')),
                    sslContext=ssl_context
                )
                content = si.RetrieveContent()
                vm_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
            except BaseException as err:
                logger.warning('Connecting to VMware instance at {0} failed: {1}'.format(
                    q.get(peer, 'credentials.address'),
                    str(err)
                ))

                failed_snapshots.append({
                    'when': 'connect',
                    'host': q.get(peer, 'credentials.address'),
                    'datastore': mapping['datastore'],
                    'error': getattr(err, 'msg', str(err))
                })

                continue

            for vm in vm_view.view:
                if not any(i.info.name == mapping['datastore'] for i in vm.datastore):
                    continue

                if not vm.snapshot:
                    continue

                snapshot = find_snapshot(vm.snapshot.rootSnapshotList, vm_snapname)
                if not snapshot:
                    continue

                logger.info('Removing snapshot of VM {0} (datastore {1})'.format(
                    vm.summary.config.name,
                    mapping['datastore'])
                )

                try:
                    task.WaitForTask(snapshot.RemoveSnapshot_Task(True))
                except vmodl.MethodFault as err:
                    logger.warning('Deleting snapshot of {0} failed: {1}'.format(vm.summary.config.name, err.msg))
                    failed_snapshots.append({
                        'when': 'delete',
                        'vm': vm.summary.config.name,
                        'datastore': mapping['datastore'],
                        'error': err.msg
                    })

            connect.Disconnect(si)

        if failed_snapshots:
            descr = Template(ALERT_TEMPLATE).render(id=id, failed_snapshots=failed_snapshots)
            self.dispatcher.call_sync('alert.emit', {
                'clazz': 'VMwareSnapshotFailed',
                'target': dataset,
                'title': 'Failed to create or remove snapshot of one or more VMware virtual machines',
                'description': descr
            })


def can_be_snapshotted(vm):
    for device in vm.config.hardware.device:
        if isinstance(device, vim.VirtualPCIPassthrough):
            return False

        # consider supporting more cases of VMs that can't be snapshoted
        # https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1006392
    return True


def find_snapshot(snapshots, name):
    for i in snapshots:
        if i.name == name:
            return i.snapshot

        ret = find_snapshot(i.childSnapshotList, name)
        if ret:
            return ret

    return None


def _depends():
    return ['VolumePlugin']


def _init(dispatcher, plugin):
    plugin.register_schema_definition('VmwareDatastore', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'free_space': {'type': 'integer'},
            'virtual_machines': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'id': {'type': 'string'},
                        'name': {'type': 'string'},
                        'on': {'type': 'boolean'},
                        'snapshottable': {'type': 'boolean'}
                    }
                }
            }
        }
    })

    plugin.register_schema_definition('VmwareDatasetFilterOp', {
        'type': 'string',
        'enum': ['NONE', 'INCLUDE', 'EXCLUDE']
    })

    plugin.register_schema_definition('VmwareDataset', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'dataset': {'type': 'string'},
            'datastore': {'type': 'string'},
            'peer': {'type': 'string'},
            'vm_filter_op': {'$ref': 'VmwareDatasetFilterOp'},
            'vm_filter_entries': {
                'type': 'array',
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_provider('vmware', VMwareProvider)
    plugin.register_provider('vmware.dataset', VMwareDatasetsProvider)

    plugin.register_task_handler('vmware.dataset.create', VMWareDatasetCreateTask)
    plugin.register_task_handler('vmware.dataset.update', VMWareDatasetUpdateTask)
    plugin.register_task_handler('vmware.dataset.delete', VMWareDatasetDeleteTask)

    plugin.register_task_handler('vmware.snapshot.take', CreateVMSnapshotsTask)
    plugin.register_task_handler('vmware.snapshot.clean', DeleteVMSnapshotsTask)

    plugin.register_event_type('vmware.dataset.changed')

    if dispatcher.datastore.query('vmware.datasets', count=True) > 0:
        # To not waste cycles, we register snapshot pre- and post-creation hooks only if there's at
        # least one VMware dataset mapping
        dispatcher.register_task_hook('volume.snapshot.create:before', 'vmware.snapshot.take')
        dispatcher.register_task_hook('volume.snapshot.create:after', 'vmware.snapshot.clean')
        dispatcher.register_task_hook('volume.snapshot.create:error', 'vmware.snapshot.clean')
