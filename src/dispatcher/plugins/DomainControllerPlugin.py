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

import errno
import logging
from datastore.config import ConfigNode
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, returns
from task import ProgressTask, Provider, TaskException, TaskDescription, VerifyException


logger = logging.getLogger(__name__)


@description('Provides info about Domain Controller vm service')
class DCProvider(Provider):
    @accepts()
    @returns(h.ref('ServiceDc'))
    def get_config(self):
        config = ConfigNode('service.dc', self.configstore).__getstate__()
        return config

    def service_start(self):
        dc_vm = self.get_config()
        self.check_dc_vm_availability()
        state = self.dispatcher.call_sync(
            'vm.query',
            [('id', '=', dc_vm['vm_id'])],
            {'select': 'status', 'single': True}
        )
        if state.get('state') != 'RUNNING':
            self.dispatcher.call_task_sync('vm.start', dc_vm['vm_id'])
        if not state.get('vm_tools_available', False):
            self.dispatcher.exec_and_wait_for_event(
                'vmtools.state.changed',lambda args: args['state'] == 'HEALTHY' and  args['id'] == dc_vm['vm_id'],
                lambda: logger.info("Starting DC VM: waiting for the vm-tools to initialize"),
                160
            )


    def service_status(self):
        dc_vm = self.get_config()
        self.check_dc_vm_availability()
        state = self.dispatcher.call_sync(
            'vm.query',
            [('id', '=', dc_vm['vm_id'])],
            {'select': 'status', 'single': True}
        )
        if state.get('state') != 'RUNNING' or not state.get('vm_tools_available', False):
            raise RpcException(errno.ENOENT, "Domain Controller service is not running")
        else:
            return 'RUNNING'

    def service_stop(self):
        dc_vm = self.get_config()
        self.check_dc_vm_availability()
        self.dispatcher.call_task_sync('vm.stop', dc_vm['vm_id'])

    def service_restart(self):
        dc_vm = self.get_config()
        self.check_dc_vm_availability()
        self.dispatcher.call_task_sync('vm.reboot', dc_vm['vm_id'])

    def provide_dc_url(self):
        dc_vm = self.get_config()
        state = self.dispatcher.call_sync(
            'vm.query',
            [('id', '=', dc_vm['vm_id'])],
            {'select': 'status', 'single': True}
        )
        if dc_vm['vm_id'] and state.get('state') == 'RUNNING':
            try:
                guest_info = self.dispatcher.call_sync('vm.get_guest_info', dc_vm['vm_id'])
                addresses = []
                for name, config in guest_info['interfaces'].items():
                    if name.startswith('lo'):
                        continue
                    addresses += ['https://' + i['address'] + ':8443' for i in config['aliases'] if i['af'] != 'LINK']

                return addresses

            except RpcException:
                raise RpcException(
                    errno.ENOENT,
                    "Please wait - Domain Controller vm service is not ready or the zentyal_domain_controller " +
                    "virtual machine state was altered manually."
                )
        else:
            raise RpcException(errno.ENOENT, 'Please configure and start the Domain Controller vm service.')

    def provide_dc_ip(self):
        dc_vm = self.get_config()
        if dc_vm['vm_id'] and dc_vm['enable']:
            try:
                guest_info = self.dispatcher.call_sync('vm.get_guest_info', dc_vm['vm_id'])
                addresses = []
                for name, config in guest_info['interfaces'].items():
                    if name.startswith('lo'):
                        continue
                    addresses += [i['address'] for i in config['aliases'] if i['af'] != 'LINK']

                return addresses

            except RpcException:
                return None

    def check_dc_vm_availability(self):
        dc_vm = self.get_config()
        vm_config = self.dispatcher.call_sync('vm.query', [('id', '=', dc_vm['vm_id'])], {'single': True})
        if not vm_config or vm_config['status'].get('state') == 'ORPHANED':
            raise RpcException(errno.ENOENT, "Domain Controller vm is deleted or not configured")
        else:
            return True


@description('Configure Domain Controller vm service')
@accepts(h.ref('ServiceDc'))
class DCConfigureTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Configuring DC service'

    def describe(self, dc):
        return TaskDescription('Configuring Domain Controller vm service')

    def verify(self, dc):
        hw_capabilities = self.dispatcher.call_sync('vm.get_hw_vm_capabilities')
        if (hw_capabilities['vtx_enabled'] and hw_capabilities['unrestricted_guest']) or hw_capabilities['svm_features']:
            return ['system']
        else:
            raise VerifyException(
                errno.ENXIO,
                'Lack of the hardware virtualization support - check hardware setup.'
            )

    def run(self, dc):
        self.set_progress(0, 'Checking Domain Controller service state')
        node = ConfigNode('service.dc', self.configstore).__getstate__()
        original_volume = node['volume']
        node.update(dc)
        vm_volume = self.dispatcher.call_sync('volume.query', [('id', '=', node['volume'])], {'single': True})
        if not node.get('volume') or not vm_volume:
            raise TaskException(
                errno.ENXIO,
                'Domain controller service is hosted by the virtual machine.'
                'Please provide the valid zfs pool name for the virtual machine volume creation.'
            )

        else:
            try:
                self.dispatcher.call_sync('service.dc.check_dc_vm_availability')
                assert original_volume == node['volume']

            except (RpcException, AssertionError):
                try:
                    dc['vm_id'] = self.run_subtask_sync('vm.import', 'zentyal_domain_controller', node['volume'])
                except RpcException:
                    dc['vm_id'] = self.run_subtask_sync('vm.create', {
                        'name': 'zentyal_domain_controller',
                        'template': {'name': 'zentyal-5.0'},
                        'target': node['volume'],
                        'config': {'autostart': True}},
                        progress_callback=lambda p, m, e=None: self.chunk_progress(
                            5, 100, 'Creating Domain Controller virtual machine: ', p, m, e
                        )
                    )

            vm_config = self.dispatcher.call_sync(
                'vm.query',
                [('id', '=', dc.get('vm_id', node['vm_id']))],
                {'select': 'config', 'single': True}
            )
            if not node['enable'] and vm_config.get('autostart'):
                vm_config['autostart'] = False
            elif node['enable'] and not vm_config.get('autostart'):
                vm_config['autostart'] = True

            self.run_subtask_sync(
                'vm.update',
                dc['vm_id'] if dc.get('vm_id') else node['vm_id'],
                {'config': vm_config}
            )

        try:
            node = ConfigNode('service.dc', self.configstore)
            node.update(dc)

            self.dispatcher.dispatch_event('service.dc.changed', {
                'operation': 'update',
                'ids': None,
            })

        except RpcException as e:
            raise TaskException(errno.ENXIO,
                                'Cannot reconfigure DC vm service: {0}'.format(str(e)))


def _init(dispatcher, plugin):

    plugin.register_schema_definition('ServiceDc', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceDc']},
            'enable': {'type': 'boolean'},
            'volume': {'type': 'string'}
        },
        'additionalProperties': True,
    })

    plugin.register_provider("service.dc", DCProvider)

    plugin.register_task_handler("service.dc.update", DCConfigureTask)
