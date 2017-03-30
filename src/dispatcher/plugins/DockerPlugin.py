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

import re
import copy
import errno
import gevent
import dockerfile_parse
import dockerhub
import logging
import requests
from pathlib import PurePath
from gevent.lock import RLock
from gevent.queue import Queue
from resources import Resource
from datetime import datetime, timedelta
from task import Provider, Task, ProgressTask, TaskDescription, TaskException, query, TaskWarning, VerifyException
from cache import EventCacheStore, CacheStore
from datastore.config import ConfigNode
from freenas.utils import normalize, query as q, first_or_default, exclude
from freenas.utils.decorators import throttle
from freenas.dispatcher.rpc import generator, accepts, returns, SchemaHelper as h, RpcException, description, private
from debug import AttachRPC

logger = logging.getLogger(__name__)
collections = None
images = None
containers_state = None
containers_rename_cache = None
hosts_status_cache = None
containers_lock = None
networks_lock = None
images_lock = None

CONTAINERS_QUERY = 'containerd.docker.query_containers'
NETWORKS_QUERY = 'containerd.docker.query_networks'
IMAGES_QUERY = 'containerd.docker.query_images'

dockerfile_parser_logger = logging.getLogger('dockerfile_parse.parser')
dockerfile_parser_logger.setLevel(logging.ERROR)
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib').setLevel(logging.WARNING)

docker_names_pattern = '^[a-zA-Z0-9]+[a-zA-Z0-9._-]+$'


@description('Provides information about Docker configuration')
class DockerConfigProvider(Provider):
    @description('Returns Docker general configuration')
    @returns(h.ref('DockerConfig'))
    def get_config(self):
        return ConfigNode('container.docker', self.configstore).__getstate__()


@description('Provides information about Docker container hosts')
class DockerHostProvider(Provider):
    @description('Returns current status of Docker hosts')
    @query('DockerHost')
    @generator
    def query(self, filter=None, params=None):
        def extend(obj):
            status = hosts_status_cache.get(obj['id'])
            state = 'UP'
            if not status:
                vm_state = self.dispatcher.call_sync(
                    'vm.query',
                    [('id', '=', obj['id'])],
                    {'single': True, 'select': 'status.state'}
                )
                if vm_state in ('BOOTLOADER', 'RUNNING'):
                    state = 'CONNECTING'
                else:
                    state = 'DOWN'

            ret = {
                'id': obj['id'],
                'name': obj['name'],
                'target': obj['target'],
                'config': {
                    'memsize': q.get(obj, 'config.memsize'),
                    'ncpus': q.get(obj, 'config.ncpus')
                },
                'state': state,
                'status': status
            }

            return ret

        with self.dispatcher.get_lock('vms'):
            results = self.datastore.query_stream('vms', ('config.docker_host', '=', True), callback=extend)
        return q.query(results, *(filter or []), stream=True, **(params or {}))

    @private
    def refresh_cache(self, id):
        refresh_cache(self.dispatcher, host_id=id)


@description('Provides information about Docker containers')
class DockerContainerProvider(Provider):
    @description('Returns current status of Docker containers')
    @query('DockerContainer')
    @generator
    def query(self, filter=None, params=None):

        def extend(obj, hosts):
            obj.update(containers_state.get(obj['id'], {'running': False}))
            obj.update({
                'reachable': obj['host'] in hosts,
                'hub_url': 'https://hub.docker.com/r/{0}'.format(obj['image'].split(':')[0])
            })

            for i in obj['volumes']:
                if i['host_path'].startswith('/host'):
                    i['host_path'] = i['host_path'].replace('/host', '/mnt')

            return obj

        reachable_hosts = list(self.dispatcher.call_sync('docker.host.query', [('state', '=', 'UP')], {'select': 'id'}))

        return q.query(
            self.datastore_log.query_stream('docker.containers', callback=lambda o: extend(o, reachable_hosts)),
            *(filter or []),
            stream=True,
            **(params or {})
        )

    @description('Requests authorization token for a container console')
    @accepts(str)
    @returns(str)
    def request_serial_console(self, id):
        return self.dispatcher.call_sync('containerd.console.request_console', id)

    @description('Creates a new process inside of a container')
    @accepts(str, str)
    @returns(str)
    def create_exec(self, id, command):
        return self.dispatcher.call_sync('containerd.docker.create_exec', id, command)

    @description('Requests interactive console\'s id')
    @accepts(str)
    @returns(str)
    def request_interactive_console(self, id):
        container = self.dispatcher.call_sync('docker.container.query', [('id', '=', id)], {'single': True})
        if not container:
            raise RpcException(errno.ENOENT, 'Container {0} not found'.format(id))

        if container['interactive']:
            return id
        else:
            return self.dispatcher.call_sync('docker.container.create_exec', id, '/bin/sh')

    @description('Orders container event handler to translate a set of delete+create events into rename+update events')
    @private
    @accepts(str, str)
    def order_rename(self, id, new_name):
        containers_rename_cache.put(id, new_name)
        containers_rename_cache.put(new_name, id)

    @description('Invalidates container event rename order')
    @private
    @accepts(str, str)
    def invalidate_rename(self, id, new_name):
        containers_rename_cache.remove(id)
        containers_rename_cache.remove(new_name)


@description('Provides information about Docker user-defined networks')
class DockerNetworkProvider(Provider):
    @description('Returns information about Docker user-defined networks')
    @query('DockerNetwork')
    @generator
    def query(self, filter=None, params=None):
        hide_builtin_networks = [('name', 'nin', ('bridge', 'external', 'host', 'none'))]
        if filter:
            filter.extend(hide_builtin_networks)
        else:
            filter = hide_builtin_networks

        return q.query(
            self.datastore_log.query_stream('docker.networks'),
            *(filter or []),
            stream=True,
            **(params or {})
        )


@description('Provides information about Docker container images')
class DockerImagesProvider(Provider):
    def __init__(self):
        self.throttle_period = timedelta(
            seconds=0, minutes=0, hours=1
        )
        self.collection_cache_lifetime = timedelta(
            seconds=0, minutes=0, hours=24
        )
        self.update_collection_lock = RLock()

    @description('Returns current status of cached Docker container images')
    @query('DockerImage')
    @generator
    def query(self, filter=None, params=None):
        return images.query(*(filter or []), stream=True, **(params or {}))

    @description('Returns a result of searching Docker Hub for a specified term - part of image name')
    @accepts(str)
    @returns(h.array(h.ref('DockerHubImage')))
    @generator
    def search(self, term):
        parser = dockerfile_parse.DockerfileParser()

        with dockerhub.DockerHub() as hub:
            for i in hub.search(term):
                presets = None
                icon = None

                if i['is_automated']:
                    # Fetch dockerfile
                    try:
                        parser.content = hub.get_dockerfile(i['repo_name'])
                        presets = self.dispatcher.call_sync('containerd.docker.labels_to_presets', parser.labels)
                    except:
                        pass

                yield {
                    'name': i['repo_name'],
                    'description': i['short_description'],
                    'star_count': i['star_count'],
                    'pull_count': i['pull_count'],
                    'icon': icon,
                    'presets': presets
                }

    @description('Returns a list of docker images from a given collection')
    @returns(h.array(h.ref('DockerHubImage')))
    @accepts(str, bool)
    @generator
    def get_collection_images(self, collection='freenas', force=False):
        queue = Queue()
        gevent.spawn(self.update_collection, collection, force, queue)

        if not collections.is_valid(collection):
            for i in queue:
                yield i
            return

        collection_data = collections.get(collection)
        for i in collection_data['items']:
            yield i

    @description('Returns a full description of specified Docker container image')
    @accepts(str)
    @returns(str)
    def readme(self, repo_name):
        with dockerhub.DockerHub() as hub:
            try:
                return hub.get_repository(repo_name).get('full_description')
            except ValueError:
                return None

    @private
    def update_collection(self, collection, force=False, queue=None):
        parser = dockerfile_parse.DockerfileParser()
        items = []

        with dockerhub.DockerHub() as hub:
            with self.update_collection_lock:
                connection_error = False
                now = datetime.now()
                collection_data = collections.get(collection, {})
                conn_error = collection_data.get('connection_error')
                coll_valid = collections.is_valid(collection)
                time_since_last_update = now - collection_data.get('update_time', now)
                if not force and coll_valid and not conn_error and time_since_last_update < self.throttle_period:
                    return

                try:
                    for i in hub.get_repositories(collection):
                        presets = None
                        icon = None
                        repo_name = '{0}/{1}'.format(i['user'], i['name'])

                        if i['is_automated']:
                            # Fetch dockerfile
                            try:
                                parser.content = hub.get_dockerfile(repo_name)
                                presets = self.dispatcher.call_sync(
                                    'containerd.docker.labels_to_presets',
                                    parser.labels
                                )
                            except:
                                pass

                        item = {
                            'name': repo_name,
                            'description': i['description'],
                            'star_count': i['star_count'],
                            'pull_count': i['pull_count'],
                            'icon': icon,
                            'presets': presets,
                            'version': '0' if not presets else presets.get('version', '0')
                        }
                        items.append(item)
                        if queue:
                            queue.put(item)
                except (TimeoutError, ConnectionError):
                    connection_error = True
                finally:
                    if queue:
                        queue.put(StopIteration)

                collections.put(collection, {
                    'update_time': datetime.now(),
                    'connection_error': connection_error,
                    'items': items
                })
                ids = self.datastore.query('docker.collections', ('collection', '=', collection), select='id')
                if ids:
                    self.dispatcher.dispatch_event('docker.collection.changed', {
                        'operation': 'update',
                        'ids': ids
                    })


@description('Provides information about cached Docker container collections')
class DockerCollectionProvider(Provider):
    @description('Returns current status of cached Docker container collections')
    @query('DockerCollection')
    @generator
    def full_query(self, filter=None, params=None):
        id_filters = []
        if filter:
            for f in filter:
                if f[0] == 'id':
                    id_filters.append(f)

        if not id_filters:
            raise RpcException(errno.EINVAL, 'Collection entries have to be filtered by id')

        results = list(self.dispatcher.call_sync('docker.collection.query', id_filters))

        for r in results:
            r['images'] = list(self.dispatcher.call_sync('docker.collection.get_entries', r['id']))

        return q.query(results, *(filter or []), stream=True, **(params or {}))

    @description('Returns current status of cached Docker container collections without image entries')
    @query('DockerCollection')
    @generator
    def query(self, filter=None, params=None):
        def extend(obj):
            collection = collections.get(obj['collection'], {})
            if not collection:
                obj['status'] = 'UNKNOWN'
            elif collection.get('connection_error'):
                obj['status'] = 'ERROR'
            else:
                obj['status'] = 'OK'
            return obj

        return self.datastore.query_stream('docker.collections', *(filter or []), **(params or {}), callback=extend)

    @description('Returns a list of Docker images related to a saved collection')
    @returns(h.array(h.ref('DockerHubImage')))
    @accepts(str)
    @generator
    def get_entries(self, id):
        collection = self.dispatcher.call_sync('docker.collection.query', [('id', '=', id)], {'single': True})
        if not collection:
            raise RpcException(errno.ENOENT, 'Collection {0} not found'.format(id))

        for i in self.dispatcher.call_sync('docker.image.get_collection_images', collection['collection'], timeout=300):
            if collection['match_expr'] in i['name']:
                yield i


class DockerBaseTask(ProgressTask):
    def get_default_host(self, progress_cb=None):
        if progress_cb:
            progress_cb(0, '')
        hostid = self.dispatcher.call_sync('docker.config.get_config').get('default_host')
        if not hostid:
            hostid = self.datastore.query(
                'vms',
                ('config.docker_host', '=', True),
                single=True,
                select='id'
            )
            if hostid:
                self.run_subtask_sync('docker.config.update', {'default_host': hostid})
                return hostid

            host_name = 'docker_host_' + str(self.dispatcher.call_sync(
                'vm.query', [('name', '~', 'docker_host_')], {'count': True}
            ))

            biggest_volume = self.dispatcher.call_sync(
                'volume.query',
                [('status', '=', 'ONLINE')],
                {'sort': ['-properties.size.parsed'], 'single': True, 'select': 'id'}
            )
            if not biggest_volume:
                raise TaskException(
                    errno.ENOENT,
                    'There are no healthy online pools available. Docker host could not be created.'
                )

            self.run_subtask_sync(
                'vm.create', {
                    'name': host_name,
                    'template': {'name': 'boot2docker'},
                    'target': biggest_volume
                },
                progress_callback=progress_cb
            )

            hostid = self.dispatcher.call_sync(
                'vm.query',
                [('name', '=', host_name)],
                {'single': True, 'select': 'id'}
            )

        def match_fn(args):
            if args['operation'] == 'update':
                if hostid in args['ids']:
                    state = self.dispatcher.call_sync(
                        'docker.host.query',
                        [('id', '=', hostid)],
                        {'single': True, 'select': 'state'}
                    )
                    return state == 'UP'
            else:
                return False

        state = self.dispatcher.call_sync(
            'vm.query',
            [('id', '=', hostid)],
            {'single': True, 'select': 'status.state'}
        )

        if state and state == 'STOPPED':
            self.dispatcher.exec_and_wait_for_event(
                'docker.host.changed',
                match_fn,
                lambda: self.run_subtask_sync('vm.start', hostid),
                600
            )

        if progress_cb:
            progress_cb(100, 'Found default Docker host')
        return hostid

    def check_host_state(self, hostid):
        host = self.dispatcher.call_sync(
            'docker.host.query',
            [('id', '=', hostid)],
            {'single': True},
            timeout=300
        )

        if not host:
            raise TaskException(errno.ENOENT, 'Docker host {0} does not exist'.format(hostid))

        if host['state'] == 'DOWN':
            raise TaskException(errno.EHOSTDOWN, 'Docker host {0} is down'.format(host['name']))

    def get_container_name_and_vm_name(self, id):
        host_id, name = self.dispatcher.call_sync(
            'docker.container.query',
            [('id', '=', id)],
            {'single': True, 'select': ('host', 'names.0')}
        )
        host_name = self.dispatcher.call_sync(
            'vm.query',
            [('id', '=', host_id)],
            {'single': True, 'select': 'name'}
        )

        return name, host_name

    def get_network_name_and_vm_name(self, id):
        host_id, name = self.dispatcher.call_sync(
            'docker.network.query',
            [('id', '=', id)],
            {'single': True, 'select': ('host', 'name')}
        )
        host_name = self.dispatcher.call_sync(
            'vm.query',
            [('id', '=', host_id)],
            {'single': True, 'select': 'name'}
        )

        return name, host_name

    def get_resources(self, id):
        res_name = f'docker:{id}'
        if id and first_or_default(lambda r: r['name'] == res_name, self.dispatcher.call_sync('task.list_resources')):
            return [res_name]

        return ['docker']


@description('Updates Docker general configuration settings')
@accepts(h.ref('DockerConfig'))
class DockerUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating Docker global configuration'

    def describe(self, container):
        return TaskDescription('Updating Docker global configuration')

    def verify(self, updated_params):
        return ['docker']

    def run(self, updated_params):
        node = ConfigNode('container.docker', self.configstore)
        node.update(updated_params)
        state = node.__getstate__()
        if 'api_forwarding' in updated_params:
            try:
                if state['api_forwarding_enable']:
                    self.dispatcher.call_sync('containerd.docker.set_api_forwarding', state['api_forwarding'])
                else:
                    self.dispatcher.call_sync('containerd.docker.set_api_forwarding', None)
            except RpcException as err:
                self.add_warning(
                    TaskWarning(err.code, err.message)
                )

        self.dispatcher.dispatch_event('docker.config.changed', {
            'operation': 'update',
            'ids': []
        })


@description('Creates a Docker container')
@accepts(
    h.all_of(
        h.ref('DockerContainer'),
        h.required('names', 'image')
    ),
    bool
)
class DockerContainerCreateTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Creating a Docker container'

    def describe(self, container, update=False):
        return TaskDescription('Creating Docker container {name}', name=container['names'][0])

    def verify(self, container, update=False):
        for v in container.get('volumes', []):
            if v.get('source') and v['source'] != 'HOST' and v['host_path'].startswith('/mnt'):
                raise VerifyException(
                    errno.EINVAL,
                    '{0} is living inside /mnt, but its source is a {1} path'.format(
                        v['host_path'], v['source'].lower()
                    )
                )
            cont_path = v.get('container_path')
            if cont_path and not PurePath(cont_path).is_absolute():
                raise VerifyException(
                    errno.EINVAL,
                    'Path: "{0}" is not an absolute path'.format(cont_path)
                )

        bridge = container.get('bridge')
        network_mode = container.get('primary_network_mode')
        bridge_enabled = network_mode == 'BRIDGED'

        if bridge_enabled and not (bridge.get('dhcp') or bridge.get('address')):
            raise VerifyException(
                errno.EINVAL,
                'Either dhcp or static address must be selected for bridged container'
            )

        if network_mode in ('HOST', 'NONE') and container.get('networks'):
            raise VerifyException(
                errno.EINVAL,
                'Cannot connect networks to container with primary network mode: {0}'.format(network_mode)
            )

        return self.get_resources(container.get('host'))

    def run(self, container, update=False):
        if not update and self.datastore_log.exists('docker.containers', ('names.0', '=', container['names'][0])):
            raise TaskException(errno.EEXIST, 'Docker container {0} already exists'.format(container['names'][0]))

        self.set_progress(0, 'Checking Docker host state')
        normalize(container, {
            'hostname': None,
            'memory_limit': None,
            'volumes': [],
            'ports': [],
            'expose_ports': False,
            'autostart': False,
            'command': [],
            'environment': [],
            'interactive': False,
            'privileged': False,
            'capabilities_add': [],
            'capabilities_drop': [],
            'primary_network_mode': 'NAT',
            'networks': [],
        })

        for id in container.get('networks'):
            if not self.dispatcher.call_sync('docker.network.query', [('id', '=', id)], {'count': True}):
                raise TaskException(errno.EEXIST, 'Docker network {0} does not exist'.format(id))

        if not container.get('host'):
            container['host'] = self.get_default_host(
                lambda p, m, e=None: self.chunk_progress(0, 30, 'Looking for default Docker host:', p, m, e)
            )

        if container.get('primary_network_mode') == 'BRIDGED':
            devices = self.dispatcher.call_sync(
                'vm.query',
                [('id', '=', container.get('host'))],
                {'select': 'devices', 'single': True}
            )
            bridge_connected = first_or_default(
                lambda o: o['type'] == 'NIC' and q.get(o, 'properties.mode') == 'BRIDGED' and o['status'] == 'CONNECTED',
                devices,
                False
            )
            if not bridge_connected:
                raise TaskException(
                    errno.ENODEV,
                    'Cannot create BRIDGED container. Docker host bridged interface not connected'
                )

        self.check_host_state(container['host'])

        self.set_progress(30, 'Pulling container {0} image'.format(container['image']))

        image = self.dispatcher.call_sync(
            'docker.image.query',
            [('hosts', 'contains', container['host']), ('names', 'contains', container['image'])],
            {'single': True}
        )

        if not image and not update:
            image = container['image']
            if ':' not in image:
                image += ':latest'

            try:
                self.run_subtask_sync(
                    'docker.image.pull',
                    image,
                    container['host'],
                    progress_callback=lambda p, m, e=None: self.chunk_progress(
                        30, 90, 'Pulling container {0} image:'.format(image), p, m, e
                    )
                )
            except TaskException:
                raise TaskException(errno.ENETDOWN, 'Cannot pull container image. Check DockerHub connectivity')

        container['name'] = container['names'][0]

        self.set_progress(80, 'Creating container {0}'.format(container['name']))

        event = 'docker.container.changed'
        query = 'docker.container.query'
        if update:
            event = 'containerd.docker.container.changed'
            query = 'containerd.docker.query_containers'

        def match_fn(args):
            if args['operation'] == 'create':
                return self.dispatcher.call_sync(
                    query,
                    [('id', 'in', args['ids']), ('names.0', '=', container['name'])],
                    {'count': True}
                )
            else:
                return False

        self.dispatcher.exec_and_wait_for_event(
            event,
            match_fn,
            lambda: self.dispatcher.call_sync('containerd.docker.create_container', container, timeout=100),
            600
        )

        if container.get('networks'):
            self.set_progress(90, 'Connecting to networks')
            contid = self.dispatcher.call_sync(
                query,
                [('name', '=', container.get('name'))],
                {'select': 'id', 'single': True}
            )
            for netid in container.get('networks'):
                self.run_subtask_sync('docker.network.connect', [contid], netid)

        if container.get('autostart'):
            contid = self.dispatcher.call_sync(
                query,
                [('name', '=', container.get('name'))],
                {'select': 'id', 'single': True}
            )
            self.set_progress(95, 'Starting the container')
            self.dispatcher.exec_and_wait_for_event(
                event,
                lambda args: args['operation'] == 'update' and contid in args['ids'],
                lambda: self.dispatcher.call_sync('containerd.docker.start', contid),
                600
            )

        self.set_progress(100, 'Finished')


@description('Updates a Docker container')
@accepts(str, h.ref('DockerContainer'))
class DockerContainerUpdateTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Updating a Docker container'

    def describe(self, id, updated_fields):
        container = self.datastore_log.get_by_id('docker.containers', id)
        return TaskDescription('Updating Docker container {name}', name=q.get(container, 'names.0', ''))

    def verify(self, id, updated_fields):
        container = self.datastore_log.get_by_id('docker.containers', id) or {}

        for v in updated_fields.get('volumes', []):
            if v.get('source') and v['source'] != 'HOST' and v['host_path'].startswith('/mnt'):
                raise VerifyException(
                    errno.EINVAL,
                    '{0} is living inside /mnt, but its source is a {1} path'.format(
                        v['host_path'], v['source'].lower()
                    )
                )
            cont_path = v.get('container_path')
            if cont_path and not PurePath(cont_path).is_absolute():
                raise VerifyException(
                    errno.EINVAL,
                    'Path: "{0}" is not an absolute path'.format(cont_path)
                )

        bridge = updated_fields.get('bridge', {})
        network_mode = updated_fields.get('primary_network_mode')
        bridge_enabled = network_mode == 'BRIDGED'
        if bridge_enabled and not (bridge.get('dhcp') or bridge.get('address')):
            raise VerifyException(
                errno.EINVAL,
                'Either dhcp or static address must be selected for bridged container'
            )

        networks = updated_fields.get('networks') or container.get('networks')
        if network_mode in ('HOST', 'NONE') and networks:
            raise VerifyException(
                errno.EINVAL,
                'Cannot connect networks to container with primary network mode: {0}'.format(network_mode)
            )

        if 'running' in updated_fields:
            raise VerifyException(errno.EINVAL, 'Running parameter cannot be set')

        if 'health' in updated_fields:
            raise VerifyException(errno.EINVAL, 'Health parameter cannot be set')

        if 'web_ui_url' in updated_fields:
            raise VerifyException(errno.EINVAL, 'Web UI URL cannot be set')

        return self.get_resources(container.get('host'))

    def run(self, id, updated_fields):
        if not self.datastore_log.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        container = self.dispatcher.call_sync('docker.container.query', [('id', '=', id)], {'single': True})

        new_image = False
        if 'image' in updated_fields and container['image'] != updated_fields['image']:
            new_image = True

        container.update(updated_fields)

        fs_diff = self.dispatcher.call_sync('containerd.docker.diff_container', id)

        if not new_image and fs_diff:
            self.set_progress(0, 'Cloning old container')

            image_name = normalize_image_name(container['image'])
            image, tag = image_name.split(':', 1)
            image = re.split(r'_copy(_[0-9]+)?$', image)[0]

            image = f'{image}_copy'
            image = get_free_name(
                image,
                lambda n: self.dispatcher.call_sync(
                    'docker.image.query',
                    [('names.0', '=', f'{n}:{tag}')],
                    {'count': True}
                )
            )

            image_name = self.run_subtask_sync('docker.container.commit', id, image, tag, timeout=240)
            container['image'] = image_name

        name = q.get(container, 'names.0')
        self.dispatcher.call_sync('docker.container.order_rename', id, name)

        self.set_progress(40, 'Deleting old container')
        try:
            def do_update():
                self.run_subtask_sync(
                    'docker.container.delete',
                    id,
                    progress_callback=lambda p, m, e: self.chunk_progress(40, 70, 'Deleting the old container:', p, m, e)
                )
                self.run_subtask_sync(
                    'docker.container.create',
                    container,
                    True,
                    progress_callback=lambda p, m, e: self.chunk_progress(70, 100, 'Recreating the container', p, m, e)
                )

            self.dispatcher.exec_and_wait_for_event(
                'docker.container.changed',
                lambda args: args['operation'] == 'rename' and id in [i[0] for i in args['ids']],
                do_update,
                600
            )

        finally:
            self.dispatcher.call_sync('docker.container.invalidate_rename', id, name)


@description('Deletes a Docker container')
@accepts(str)
class DockerContainerDeleteTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting a Docker container'

    def describe(self, id):
        name = self.dispatcher.call_sync(
            'docker.container.query', [('id', '=', id)], {'single': True, 'select': 'names.0'}
        )
        return TaskDescription('Deleting Docker container {name}', name=name or id)

    def verify(self, id):
        host_id = self.datastore_log.query('docker.containers', ('id', '=', id), single=True, select='host')
        return self.get_resources(host_id)

    def run(self, id):
        if not self.datastore_log.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', id)
        except RpcException:
            name, host_name = self.get_container_name_and_vm_name(id)

            self.datastore_log.delete('docker.containers', id)
            self.dispatcher.dispatch_event('docker.container.changed', {
                'operation': 'delete',
                'ids': [id]
            })

            self.add_warning(TaskWarning(
                errno.EACCES,
                'Cannot access Docker Host {0}. Container {1} was deleted from the local cache only.'.format(
                    host_name or '',
                    name
                )
            ))

            return

        self.dispatcher.exec_and_wait_for_event(
            'containerd.docker.container.changed',
            lambda args: args['operation'] == 'delete' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.delete_container', id),
            600
        )


@description('Starts a Docker container')
@accepts(str)
class DockerContainerStartTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Starting container'

    def describe(self, id):
        name = self.dispatcher.call_sync(
            'docker.container.query', [('id', '=', id)], {'single': True, 'select': 'names.0'}
        )
        return TaskDescription('Starting container {name}', name=name or id)

    def verify(self, id):
        host_id = self.datastore_log.query('docker.containers', ('id', '=', id), single=True, select='host')
        return self.get_resources(host_id)

    def run(self, id):
        if not self.datastore_log.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        primary_network_mode, expose_ports, ports = self.dispatcher.call_sync(
            'docker.container.query',
            [('id', '=', id)],
            {'select': ['primary_network_mode', 'expose_ports', 'ports'], 'single': True}
        )

        if primary_network_mode == 'NAT' and expose_ports:
            required_tcp_ports = [e['host_port'] for e in ports if e['protocol'] == 'TCP']
            required_udp_ports = [e['host_port'] for e in ports if e['protocol'] == 'UDP']
            conflicting_tcp_ports = self.dispatcher.call_sync(
                'network.port.query',
                [('port', 'in', required_tcp_ports), ('protocol', '~', 'TCP')],
                {'select': ['port', 'consumer_name']}
            )
            conflicting_udp_ports = self.dispatcher.call_sync(
                'network.port.query',
                [('port', 'in', required_udp_ports), ('protocol', '~', 'UDP')],
                {'select': ['port', 'consumer_name']}
            )
            msg = ""
            if conflicting_tcp_ports:
                msg += "TCP port/consumer list: "+", ".join(["{0}/{1}".format(e[0], e[1]) for e in conflicting_tcp_ports])+"; "
            if conflicting_udp_ports:
                msg += "UDP port/consumer list: "+", ".join(["{0}/{1}".format(e[0], e[1]) for e in conflicting_udp_ports])
            if msg:
                raise TaskException(
                    errno.EINVAL,
                    'Conflicting ports detected. {0}'.format(msg)
                )

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', id)
        except RpcException:
            name, host_name = self.get_container_name_and_vm_name(id)
            raise TaskException(
                errno.EINVAL,
                'Docker Host {0} is currently unreachable. Cannot start {1} container'.format(host_name or '', name)
            )

        self.dispatcher.exec_and_wait_for_event(
            'docker.container.changed',
            lambda args: args['operation'] == 'update' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.start', id),
            600
        )


@description('Stops a Docker container')
@accepts(str)
class DockerContainerStopTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Stopping container'

    def describe(self, id):
        name = self.dispatcher.call_sync(
            'docker.container.query', [('id', '=', id)], {'single': True, 'select': 'names.0'}
        )
        return TaskDescription('Stopping container {name}', name=name or id)

    def verify(self, id):
        host_id = self.datastore_log.query('docker.containers', ('id', '=', id), single=True, select='host')
        return self.get_resources(host_id)

    def run(self, id):
        if not self.datastore_log.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        self.dispatcher.exec_and_wait_for_event(
            'docker.container.changed',
            lambda args: args['operation'] == 'update' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.stop', id),
            600
        )


@description('Retarts a Docker container')
@accepts(str)
class DockerContainerRestartTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Restarting container'

    def describe(self, id):
        name = self.dispatcher.call_sync(
            'docker.container.query', [('id', '=', id)], {'single': True, 'select': 'names.0'}
        )
        return TaskDescription('Restarting container {name}', name=name or id)

    def verify(self, id):
        host_id = self.datastore_log.query('docker.containers', ('id', '=', id), single=True, select='host')
        return self.get_resources(host_id)

    def run(self, id):
        if not self.datastore_log.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', id)
        except RpcException:
            name, host_name = self.get_container_name_and_vm_name(id)
            raise TaskException(
                errno.EINVAL,
                'Docker Host {0} is currently unreachable. Cannot restart {1} container'.format(host_name or '', name)
            )

        self.dispatcher.exec_and_wait_for_event(
            'docker.container.changed',
            lambda args: args['operation'] == 'update' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.restart', id),
            600
        )


@description('Clones a Docker container')
@accepts(str, str)
@returns(str)
class DockerContainerCloneTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Cloning a Docker container'

    def describe(self, id, new_name):
        container = self.datastore_log.get_by_id('docker.containers', id)
        return TaskDescription(
            'Cloning Docker container {name} to {new_name}',
            name=q.get(container, 'names.0', ''),
            new_name=new_name
        )

    def verify(self, id, new_name):
        host_id = self.datastore_log.query('docker.containers', ('id', '=', id), single=True, select='host')
        return self.get_resources(host_id)

    def run(self, id, new_name):
        if not self.datastore_log.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        if self.datastore_log.exists('docker.containers', ('names.0', '=', new_name)):
            raise TaskException(errno.EEXIST, 'Docker container {0} already exists'.format(new_name))

        container = self.dispatcher.call_sync('docker.container.query', [('id', '=', id)], {'single': True})

        self.set_progress(30, 'Committing a new image {0} from the container {1}'.format(
            new_name,
            q.get(container, 'names.0')
        ))

        image_name = normalize_image_name(container['image'])
        image, tag = image_name.split(':', 1)
        image = f'{image}_clone'
        image = get_free_name(
            image,
            lambda n: self.dispatcher.call_sync('docker.image.query', [('names.0', '=', f'{n}:{tag}')], {'count': True})
        )

        image_name = self.run_subtask_sync('docker.container.commit', id, image, tag)

        container.pop('id')
        q.set(container, 'names.0', new_name)
        container['image'] = image_name

        return self.run_subtask_sync(
            'docker.container.create',
            container,
            progress_callback=lambda p, m, e: self.chunk_progress(50, 100, '', p, m, e)
        )


@description('Commits a new image from existing Docker container')
@accepts(str, str, h.one_of(str, None))
@returns(str)
class DockerContainerCommitTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Committing a Docker image'

    def describe(self, id, name, tag=None):
        return TaskDescription('Committing the Docker image {name}', name=name)

    def verify(self, id, name, tag=None):
        host_id = self.datastore_log.query('docker.containers', ('id', '=', id), single=True, select='host')
        return self.get_resources(host_id)

    def run(self, id, name, tag=None):
        if not self.datastore_log.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        if self.dispatcher.call_sync('docker.image.query', [('names.0', '=', name)], {'count': True}):
            raise TaskException(errno.EEXIST, 'Docker image {0} already exists'.format(name))

        if not tag:
            tag = 'latest'

        name = f'{name}:{tag}'

        if '/' not in name:
            name = f'freenas/{name}'

        def match_fn(args):
            if args['operation'] == 'create':
                return bool(self.dispatcher.call_sync(
                    'docker.image.query',
                    [('names.0', '=', name)],
                    {'count': True}
                ))
            else:
                return False

        def call_and_get_name():
            nonlocal name
            name = self.dispatcher.call_sync('containerd.docker.commit_image', id, name)

        self.dispatcher.exec_and_wait_for_event(
            'docker.image.changed',
            match_fn,
            call_and_get_name
        )

        return name


@description('Creates a Docker network')
@accepts(h.all_of(
    h.ref('DockerNetwork'),
    h.required('name')
))
class DockerNetworkCreateTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Creating a Docker network'

    def describe(self, network):
        return TaskDescription('Creating Docker network {name}', name=network['name'])

    def verify(self, network):
        if network.get('gateway') and not network.get('subnet'):
            raise TaskException(errno.EINVAL, 'Docker network subnet property is not specified')

        if network.get('subnet') and not network.get('gateway'):
            raise TaskException(errno.EINVAL, 'Docker network gateway property is not specified')

        return self.get_resources(network.get('host'))

    def run(self, network):
        if self.datastore_log.exists('docker.networks', ('name', '=', network['name'])):
            raise TaskException(errno.EEXIST, 'Docker network {0} already exists'.format(network['name']))

        normalize(network, {
            'host': None,
            'driver': 'bridge',
            'subnet': None,
            'gateway': None,
            'containers': []
        })

        for id in network.get('containers'):
            if not self.dispatcher.call_sync('docker.container.query', [('id', '=', id)], {'count': True}):
                raise TaskException(errno.EEXIST, 'Docker container {0} does not exist'.format(id))

        if not network.get('host'):
            network['host'] = self.get_default_host(
                lambda p, m, e=None: self.chunk_progress(0, 30, 'Looking for default Docker host:', p, m, e)
            )

        self.check_host_state(network['host'])

        def match_fn(args):
            if args['operation'] == 'create':
                return self.dispatcher.call_sync(
                    'docker.network.query',
                    [('id', 'in', args['ids']), ('name', '=', network['name'])],
                    {'single': True}
                )
            else:
                return False

        self.dispatcher.exec_and_wait_for_event(
            'docker.network.changed',
            match_fn,
            lambda: self.dispatcher.call_sync('containerd.docker.create_network', network)
        )

        if network.get('containers'):
            netid = self.dispatcher.call_sync(
                'docker.network.query',
                [('name', '=', network.get('name'))],
                {'select': 'id', 'single': True}
            )
            self.run_subtask_sync('docker.network.connect', network.get('containers'), netid)


@description('Updates a Docker network')
@accepts(str, h.ref('DockerNetwork'))
class DockerNetworkUpdateTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Updating a Docker network'

    def describe(self, id, updated_fields):
        network = self.datastore_log.get_by_id('docker.networks', id)
        return TaskDescription('Updating Docker network {name}', name=q.get(network, 'name', ''))

    def verify(self, id, updated_fields):
        host_id = self.datastore_log.query('docker.networks', ('id', '=', id), single=True, select='host')
        return self.get_resources(host_id)

    def run(self, id, updated_fields):
        if not self.datastore_log.exists('docker.networks', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker network {0} does not exist'.format(id))

        network = self.dispatcher.call_sync('docker.network.query', [('id', '=', id)], {'single': True})
        network.update(updated_fields)

        self.set_progress(0, 'Deleting old network')
        self.run_subtask_sync(
            'docker.network.delete',
            id,
            progress_callback=lambda p, m, e: self.chunk_progress(0, 50, 'Deleting the old network:', p, m, e)
        )
        self.run_subtask_sync(
            'docker.network.create',
            network,
            progress_callback=lambda p, m, e: self.chunk_progress(50, 100, 'Recreating the network', p, m, e)
        )


@description('Deletes a Docker network')
@accepts(str)
class DockerNetworkDeleteTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting a Docker network'

    def describe(self, id):
        name = self.dispatcher.call_sync(
            'docker.network.query', [('id', '=', id)], {'single': True, 'select': 'name'}
        )
        return TaskDescription('Deleting Docker network {name}', name=name or id)

    def verify(self, id):
        name = self.dispatcher.call_sync('docker.network.query', [('id', '=', id)], {'single': True, 'select': 'name'})
        if name in ('bridge', 'external', 'host', 'none'):
            raise TaskException(errno.EINVAL, 'Cannot delete built-in network "{0}"'.format(name))

        host_id = self.datastore_log.query('docker.networks', ('id', '=', id), single=True, select='host')
        return self.get_resources(host_id)

    def run(self, id):
        name, containers = self.dispatcher.call_sync(
            'docker.network.query',
            [('id', '=', id)],
            {'select': ['name', 'containers'], 'single': True}
        )
        if not name:
            raise TaskException(errno.ENOENT, 'Docker network {0} does not exist'.format(id))

        if containers:
            self.run_subtask_sync('docker.network.disconnect', containers, id)

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_network_id', id)
        except RpcException:
            name, host_name = self.get_network_name_and_vm_name(id)

            self.datastore_log.delete('docker.networks', id)
            self.dispatcher.dispatch_event('docker.network.changed', {
                'operation': 'delete',
                'ids': [id]
            })

            self.add_warning(TaskWarning(
                errno.EACCES,
                'Cannot access Docker Host {0}. Network {1} was deleted from the local cache only.'.format(
                    host_name or '',
                    name
                )
            ))

            return

        self.dispatcher.exec_and_wait_for_event(
            'docker.network.changed',
            lambda args: args['operation'] == 'delete' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.delete_network', id),
            100
        )


@description('Connects selected containers to a network')
@accepts(h.array(str), str)
class DockerNetworkConnectTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Connecting containers to network'

    def describe(self, container_ids, network_id):
        contnames = list(self.dispatcher.call_sync(
            'docker.container.query',
            [('id', 'in', container_ids)],
            {'select': 'name'}
        ))
        netname = self.dispatcher.call_sync(
            'docker.network.query',
            [('id', '=', network_id)],
            {'single': True, 'select': 'name'}
        )
        return TaskDescription(
            'Connecting containers {contnames} to network {name}',
            contnames=','.join(contnames or container_ids),
            name=netname or network_id
        )

    def verify(self, container_ids=None, network_id=None):
        if not container_ids or not network_id:
            raise TaskException(errno.EINVAL, 'Both container(s) and network must be specified')

        host_id = self.datastore_log.query(
            'docker.containers',
            ('id', '=', container_ids[0]),
            single=True,
            select='host'
        )
        return self.get_resources(host_id)

    def run(self, container_ids, network_id):
        for id in container_ids:
            if not self.datastore_log.exists('docker.containers', ('id', '=', id)):
                raise TaskException(errno.ENOENT, 'Docker container {0} not found'.format(id))

        network = self.dispatcher.call_sync('docker.network.query', [('id', '=', network_id)], {'single': True})
        if not network:
            raise TaskException(errno.ENOENT, 'Docker network {0} does not exist'.format(network['name']))

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', container_ids[0])
        except RpcException:
            _, host_name = self.get_container_name_and_vm_name(container_ids[0])
            raise TaskException(
                errno.EINVAL,
                'Docker Host {0} is currently unreachable.'.format(host_name or '')
            )

        for id in container_ids:
            self.dispatcher.exec_and_wait_for_event(
                'docker.container.changed',
                lambda args: args['operation'] == 'update' and id in args['ids'],
                lambda: self.dispatcher.call_sync(
                    'containerd.docker.connect_container_to_network', id, network_id),
                600
            )


@description('Disconnects selected containers from a network')
@accepts(h.array(str), str)
class DockerNetworkDisconnectTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Disconnecting containers from network'

    def describe(self, container_ids, network_id):
        contnames = list(self.dispatcher.call_sync(
            'docker.container.query',
            [('id', 'in', container_ids)],
            {'select': 'name'}
        ))
        netname = self.dispatcher.call_sync(
            'docker.network.query',
            [('id', '=', network_id)],
            {'single': True, 'select': 'name'}
        )
        return TaskDescription(
            'Disconnecting containers {contnames} from network {name}',
            contnames=','.join(contnames or container_ids),
            name=netname or network_id
        )

    def verify(self, container_ids=None, network_id=None):
        if not container_ids or not network_id:
            raise TaskException(errno.EINVAL, 'Both container(s) and network must be specified')

        host_id = self.datastore_log.query(
            'docker.containers',
            ('id', '=', container_ids[0]),
            single=True,
            select='host'
        )
        return self.get_resources(host_id)

    def run(self, container_ids, network_id):
        for id in container_ids:
            if not self.datastore_log.exists('docker.containers', ('id', '=', id)):
                raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        network = self.dispatcher.call_sync('docker.network.query', [('id', '=', network_id)], {'single': True})
        if not network:
            raise TaskException(errno.ENOENT, 'Docker network {0} does not exist'.format(network['name']))

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', container_ids[0])
        except RpcException:
            _, host_name = self.get_container_name_and_vm_name(container_ids[0])
            raise TaskException(
                errno.EINVAL,
                'Docker Host {0} is currently unreachable.'.format(host_name or '')
            )

        for cid in container_ids:
            self.dispatcher.exec_and_wait_for_event(
                'docker.container.changed',
                lambda args: args['operation'] == 'update' and cid in args['ids'],
                lambda: self.dispatcher.call_sync(
                    'containerd.docker.disconnect_container_from_network', cid, network_id),
                600
            )


@description('Pulls a selected container image from Docker Hub and caches it on specified Docker host')
@accepts(str, h.one_of(str, None))
class DockerImagePullTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Pulling docker image'

    def describe(self, name, hostid=None):
        return TaskDescription('Pulling docker image {name}', name=name)

    def verify(self, name, hostid=None):
        return self.get_resources(hostid)

    def run(self, name, hostid=None):
        if not hostid:
            hostid = self.get_default_host(
                lambda p, m, e=None: self.chunk_progress(0, 10, 'Looking for default Docker host:', p, m, e)
            )

        if ':' not in name:
            name += ':latest'

        if '/' not in name:
            name = 'library/' + name

        hosts = self.dispatcher.call_sync(
            'docker.image.query',
            [('names.0', '=', name)],
            {'select': 'hosts', 'single': True}
        )
        if isinstance(hosts, list):
            hosts.append(hostid)
        else:
            hosts = [hostid]

        hosts = list(set(hosts))

        hosts_progress = {}
        token_rsp = requests.get(
            'https://auth.docker.io/token?service=registry.docker.io&scope=repository:{0}:pull'.format(
                name.split(':')[0]
            )
        )
        if token_rsp.ok:
            manifest = requests.get(
                'https://registry-1.docker.io/v2/{0}/manifests/{1}'.format(*name.split(':', 1)),
                headers={'Authorization': 'Bearer {}'.format(token_rsp.json()['token'])}
            )
            if manifest.ok:
                layers = manifest.json()['fsLayers']
                layers_len = len(layers)
                weight = 1 / (layers_len * len(hosts))
                layers_progress = {l['blobSum'].split(':', 1)[1]: {'Downloading': 0, 'Extracting': 0} for l in layers}
                hosts_progress = {h: copy.deepcopy(layers_progress) for h in hosts}

        @throttle(seconds=1)
        def report_progress(message):
            nonlocal weight
            nonlocal hosts_progress
            progress = 0
            for h in hosts_progress.values():
                for l in h.values():
                    progress += (l['Downloading'] * 0.6 + l['Extracting'] * 0.4) * weight

            progress = 10 + progress * 0.9
            self.set_progress(progress, message)

        for h in hosts:
            try:
                self.check_host_state(h)
            except TaskException:
                continue

            for i in self.dispatcher.call_sync('containerd.docker.pull', name, h, timeout=3600):
                if 'progressDetail' in i and 'current' in i['progressDetail'] and 'total' in i['progressDetail']:
                    if token_rsp.ok and manifest.ok:
                        id = i.get('id', '')
                        status = i.get('status')
                        _, layer = first_or_default(lambda o: o[0].startswith(id), hosts_progress[h].items())
                        if status in ('Downloading', 'Extracting'):
                            layer[status] = i['progressDetail']['current'] / i['progressDetail']['total'] * 100

                        report_progress('{0} layer {1}'.format(i.get('status', ''), i.get('id', '')))
                    else:
                        self.set_progress(None, '{0} layer {1}'.format(i.get('status', ''), i.get('id', '')))


@description('Removes previously cached container image from a Docker host/s')
@accepts(str, h.one_of(str, None))
@returns(bool)
class DockerImageDeleteTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting docker image'

    def describe(self, id, hostid=None):
        name = self.dispatcher.call_sync('docker.image.query', [('id', '=', id)], {'single': True, 'select': 'names.0'})
        return TaskDescription('Deleting docker image {name}', name=name or '')

    def verify(self, id, hostid=None):
        return self.get_resources(hostid)

    def run(self, id, hostid=None):
        name = self.dispatcher.call_sync('docker.image.query', [('id', '=', id)], {'single': True, 'select': 'names.0'})
        if not name:
            raise TaskException(errno.ENOENT, f'Docker container image {id} does not exist')

        childs = list(self.dispatcher.call_sync('docker.image.query', [('parent', '=', id)], {'select': 'names.0'}))
        if childs:
            raise TaskException(
                errno.EACCES,
                f'Cannot delete image {name}. Image has local child images: ' + ', '.join(childs)
            )

        if hostid:
            hosts = [hostid]
        else:
            hosts = list(self.dispatcher.call_sync(
                'docker.image.query',
                [('id', '=', id)],
                {'select': 'hosts', 'single': True}
            ))

        related = self.dispatcher.call_sync(
            'docker.container.query',
            [('host', 'in', hosts), ('image_id', '=', id)],
            {'select': ('host', 'names.0')}
        )
        names_in_use = []
        clean_sweep = True
        for h, n in related:
            if h in hosts:
                hosts.remove(h)
                clean_sweep = False
            names_in_use.append(n)

        if names_in_use:
            self.add_warning(TaskWarning(
                errno.EACCES,
                f'There are containers using {name} image on selected Docker hosts - delete them first: ' +
                ', '.join(names_in_use)
            ))

        def delete_image():
            for h_id in hosts:
                try:
                    self.check_host_state(h_id)
                except TaskException:
                    continue

                try:
                    self.dispatcher.call_sync('containerd.docker.delete_image', id, h_id)
                except RpcException as err:
                    raise TaskException(errno.EACCES, 'Failed to remove image {0}: {1}'.format(name, err))

        def match_fn(args):
            if args['operation'] == 'delete':
                return id in args['ids']
            else:
                return False

        if hosts:
            self.dispatcher.exec_and_wait_for_event(
                'docker.image.changed',
                match_fn,
                lambda: delete_image(),
                600
            )

        return clean_sweep


@description('Removes all previously cached container images')
class DockerImageFlushTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting all docker images'

    def describe(self):
        return TaskDescription('Deleting all docker images')

    def verify(self):
        return ['docker']

    def run(self):
        self.set_progress(0, 'Deleting docker images')
        done = 0
        failed = []
        images_cnt = self.dispatcher.call_sync('docker.image.query', [], {'count': True})
        while True:
            images = list(self.dispatcher.call_sync('docker.image.query', [], {'select': ('id', 'parent')}))
            start_done = done
            for image in list(images):
                if image not in failed:
                    if not first_or_default(lambda i: i[1] == image[0], images):
                        success = self.run_subtask_sync('docker.image.delete', image[0])
                        done += 1
                        self.set_progress(int((done / images_cnt) * 100), 'Deleting docker images')
                        if success:
                            images.remove(image)
                        else:
                            failed.append(image)

            if start_done == done:
                for image in images:
                    name = self.dispatcher.call_sync(
                        'docker.image.query', [('id', '=', image[0])], {'single': True, 'select': 'names.0'}
                    )
                    childs = list(self.dispatcher.call_sync(
                        'docker.image.query', [('parent', '=', image[0])], {'select': 'names.0'}
                    ))
                    if not childs:
                        continue

                    self.add_warning(TaskWarning(
                        errno.EACCES,
                        f'Cannot delete {name}. Delete local child images first: ' + ', '.join(childs)
                    ))
                break


@accepts(h.all_of(
    h.ref('DockerHost'),
    h.required('name', 'target')
))
@returns(str)
@description('Creates a Docker host')
class DockerHostCreateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Creating a Docker host'

    def describe(self, host):
        return TaskDescription('Creating the Docker host {name}', name=host.get('name', ''))

    def verify(self, host):
        try:
            resources = self.dispatcher.call_sync('vm.datastore.get_resources', host['target'])
        except RpcException as err:
            raise VerifyException(err.code, 'Invalid datastore: {0}'.format(err.message))

        resources.append('docker')
        return resources

    def run(self, host):
        if self.datastore.exists('vms', ('name', '=', host['name'])):
            raise TaskException(errno.EEXIST, 'VM {0} already exists'.format(host['name']))

        q.set(host, 'template.name', 'boot2docker')

        id = self.run_subtask_sync_with_progress('vm.create', host)

        return id


@accepts(str, h.ref('DockerHost'))
@description('Updates a Docker host')
class DockerHostUpdateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Updating a Docker host'

    def describe(self, id, updated_params):
        host = self.dispatcher.call_sync('docker.host.query', [('id', '=', id)], {'single': True}) or {}
        return TaskDescription('Updating the Docker host {name}', name=host.get('name', ''))

    def verify(self, id, updated_params):
        if 'target' in updated_params:
            raise VerifyException(errno.EINVAL, 'Target datastore cannot be changed')

        host = self.dispatcher.call_sync('docker.host.query', [('id', '=', id)], {'single': True})
        resources = []
        if host:
            try:
                resources = self.dispatcher.call_sync('vm.datastore.get_resources', host['target'])
            except RpcException as err:
                raise VerifyException(err.code, 'Invalid datastore: {0}'.format(err.message))

        resources.append('docker')
        return resources

    def run(self, id, updated_params):
        if not self.datastore.exists('vms', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker host {0} does not exist'.format(id))

        vm = self.datastore.query('vms', ('id', '=', id), single=True)

        diff = {}
        if 'name' in updated_params:
            diff['name'] = updated_params['name']

        if 'config' in updated_params:
            diff['config'] = vm['config']
            updated_config = updated_params['config']

            if 'ncpus' in updated_config:
                q.set(diff, 'config.ncpus', updated_config['ncpus'])

            if 'memsize' in updated_config:
                q.set(diff, 'config.memsize', updated_config['memsize'])

        return self.run_subtask_sync_with_progress('vm.update', id, diff)


@accepts(str)
@description('Deletes a Docker host')
class DockerHostDeleteTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting a Docker host'

    def describe(self, id):
        host = self.dispatcher.call_sync('docker.host.query', [('id', '=', id)], {'single': True}) or {}
        return TaskDescription('Deleting the Docker host {name}', name=host.get('name', ''))

    def verify(self, id):
        host = self.dispatcher.call_sync('docker.host.query', [('id', '=', id)], {'single': True})
        resources = []
        if host:
            try:
                resources = self.dispatcher.call_sync('vm.datastore.get_resources', host['target'])
            except RpcException as err:
                raise VerifyException(err.code, 'Invalid datastore: {0}'.format(err.message))

        resources.append('docker')
        return resources

    def run(self, id):
        if not self.datastore.exists('vms', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker host {0} does not exist'.format(id))

        return self.run_subtask_sync_with_progress('vm.delete', id)


@accepts(h.all_of(
    h.ref('DockerCollection'),
    h.forbidden('images')
))
@returns(str)
@description('Creates a known Docker cache collection')
class DockerCollectionCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating known collection of containers'

    def describe(self, collection):
        return TaskDescription('Creating known collection of containers {name}', name=collection.get('name', ''))

    def verify(self, collection):
        if 'name' not in collection:
            raise RpcException(errno.EINVAL, 'Collection name has to be specified')
        if 'collection' not in collection:
            raise RpcException(errno.EINVAL, 'Name of Dockerhub collection has to be specified')

        return ['docker']

    def run(self, collection):
        normalize(collection, {
            'match_expr': ''
        })

        if self.datastore.exists('docker.collections', ('name', '=', collection['name'])):
            raise TaskException(errno.EEXIST, 'Containers collection {0} already exists'.format(collection['name']))

        id = self.datastore.insert('docker.collections', collection)
        self.dispatcher.dispatch_event('docker.collection.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@accepts(str, h.all_of(
    h.ref('DockerCollection'),
    h.forbidden('images')
))
@description('Updates a known Docker cache collection')
class DockerCollectionUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating known collection of containers'

    def describe(self, id, updated_params):
        collection = self.datastore.get_by_id('docker.collections', id)
        return TaskDescription('Updating known collection of containers {name}', name=collection.get(''))

    def verify(self, id, updated_params):
        return ['docker']

    def run(self, id, updated_params):
        if not self.datastore.exists('docker.collections', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker collection {0} not found'.format(id))
        collection = self.datastore.get_by_id('docker.collections', id)

        collection.update(updated_params)
        if 'name' in updated_params and self.datastore.exists('docker.collections', ('name', '=', collection['name'])):
            raise TaskException(errno.EEXIST, 'Docker collection {0} already exists'.format(collection['name']))

        self.datastore.update('docker.collections', id, collection)
        self.dispatcher.dispatch_event('docker.collection.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str)
@description('Deletes a known Docker cache collection')
class DockerCollectionDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting known collection of containers'

    def describe(self, id):
        collection = self.datastore.get_by_id('docker.collections', id)
        return TaskDescription('Deleting known collection of containers {name}', name=collection.get(''))

    def verify(self, id):
        return ['docker']

    def run(self, id):
        if not self.datastore.exists('docker.collections', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker collection {0} not found'.format(id))

        self.datastore.delete('docker.collections', id)

        self.dispatcher.dispatch_event('docker.collection.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@accepts(str, bool)
@returns(h.array(h.ref('DockerHubImage')))
@description('Returns a list of Docker images related to a saved collection')
class DockerCollectionGetPresetsTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Downloading Docker collection presets'

    def describe(self, id, force=False):
        collection = self.datastore.get_by_id('docker.collections', id)
        return TaskDescription('Downloading Docker collection {name} presets', name=collection.get(''))

    def verify(self, id, force=False):
        return []

    def run(self, id, force=False):
        if not self.datastore.exists('docker.collections', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker collection {0} not found'.format(id))

        result = []
        collection = self.datastore.get_by_id('docker.collections', id)
        name = collection['name']
        cn_name = collection['collection']

        self.set_progress(0, 'Downloading {0} collection presets'.format(name))

        with dockerhub.DockerHub() as hub:
            collection_len = len([i for i in hub.get_repositories(cn_name) if collection['match_expr'] in i['name']])

        for i in self.dispatcher.call_sync('docker.image.get_collection_images', cn_name, force):
            result.append(i)
            self.set_progress((len(result) / collection_len) * 100, 'Downloading {0} collection presets'.format(name))

        return result


def get_free_name(base, condition):
    cnt = 0
    name = base
    while condition(name):
        cnt += 1
        name = f'{base}_{cnt - 1}'

    return name


def normalize_image_name(name):
    if '/' not in name:
        name = f'freenas/{name}'

    if ':' not in name:
        name = f'{name}:latest'

    return name


def refresh_database_cache(dispatcher, collection, event, query, lock, ids=None, host_id=None, rename_cache=None):
    filter = []
    if ids:
        logger.debug(f'Refreshing Docker {collection} cache - containers: ' + ', '.join(ids))
        filter.append(('id', 'in', ids))

    if host_id:
        logger.debug(f'Refreshing Docker {collection} cache - host: {host_id}')
        filter.append(('host', '=', host_id))
    else:
        logger.debug(f'Refreshing Docker {collection} cache')
        active_hosts = list(dispatcher.call_sync('docker.host.query', [('state', '=', 'UP')], {'select': 'id'}))
        filter.append(('host', 'in', active_hosts))

    with lock:
        current = list(dispatcher.call_sync(query, filter))
        old = dispatcher.datastore_log.query(collection, *filter)
        created = []
        updated = []
        renamed = []
        deleted = []
        for obj in map(lambda o: exclude(o, 'running', 'health'), current):
            old_obj = first_or_default(lambda o: o['id'] == obj['id'], old)
            new_id = obj['id']
            changed = True

            if dispatcher.datastore_log.exists(collection, ('id', '=', new_id)):
                if obj != old_obj:
                    updated.append(new_id)
                else:
                    changed = False
            else:
                if rename_cache:
                    name = q.get(obj, 'names.0')
                    old_id = rename_cache.get(name)

                    if old_id:
                        renamed.append([old_id, new_id])
                        rename_cache.remove(name)
                        updated.append(new_id)
                        continue

                created.append(new_id)

            if changed:
                dispatcher.datastore_log.update(collection, new_id, obj, upsert=True)

        for obj in old:
            old_id = obj['id']
            if not first_or_default(lambda o: o['id'] == old_id, current):
                if dispatcher.datastore_log.exists(collection, ('id', '=', old_id)):
                    dispatcher.datastore_log.delete(collection, obj['id'])
                    if not rename_cache or not rename_cache.get(old_id):
                        deleted.append(obj['id'])

        if rename_cache:
            for old_id, new_id in renamed:
                rename_cache.remove(old_id)

        if renamed:
            logger.trace(f'Renamed in {collection}: {renamed}')
            dispatcher.dispatch_event(event, {
                'operation': 'rename',
                'ids': renamed
            })

        if updated:
            logger.trace(f'Updated in {collection}: {updated}')
            dispatcher.dispatch_event(event, {
                'operation': 'update',
                'ids': updated
            })

        if created:
            logger.trace(f'Created in {collection}: {created}')
            dispatcher.dispatch_event(event, {
                'operation': 'create',
                'ids': created
            })

        if deleted:
            logger.trace(f'Deleted in {collection}: {deleted}')
            dispatcher.dispatch_event(event, {
                'operation': 'delete',
                'ids': deleted
            })


def refresh_networks(dispatcher, ids=None, host_id=None):
    refresh_database_cache(
        dispatcher=dispatcher,
        collection='docker.networks',
        event='docker.network.changed',
        query=NETWORKS_QUERY,
        lock=networks_lock,
        ids=ids,
        host_id=host_id,
        rename_cache=None
    )


def refresh_containers(dispatcher, ids=None, host_id=None):
    refresh_database_cache(
        dispatcher=dispatcher,
        collection='docker.containers',
        event='docker.container.changed',
        query=CONTAINERS_QUERY,
        lock=containers_lock,
        ids=ids,
        host_id=host_id,
        rename_cache=containers_rename_cache
    )


def sync_images(dispatcher, ids=None, host_id=None):
    filter = []
    if ids:
        logger.debug('Refreshing Docker image cache - images: ' + ', '.join(ids))
        filter.append(('id', 'in', ids))

    if host_id:
        logger.debug(f'Refreshing Docker image cache - host: {host_id}')
        filter.append(('hosts', 'contains', host_id))
    else:
        logger.debug('Refreshing Docker image cache')

    with images_lock:
        objects = list(dispatcher.call_sync(IMAGES_QUERY, filter))
        images.update(**{i['id']: i for i in objects})
        if not ids:
            nonexistent_ids = []
            for k, v in images.itervalid():
                if not first_or_default(lambda o: o['id'] == k, objects):
                    nonexistent_ids.append(k)

            images.remove_many(nonexistent_ids)


def refresh_cache(dispatcher, ids=None, host_id=None):
    logger.debug('Syncing Docker containers, networks, image cache')

    sync_images(dispatcher, ids=ids, host_id=host_id)
    refresh_containers(dispatcher, ids=ids, host_id=host_id)
    refresh_networks(dispatcher, ids=ids, host_id=host_id)

    if not images.ready:
        logger.debug('Docker images cache initialized')
        images.ready = True


def collect_debug(dispatcher):
    yield AttachRPC('hosts-query', 'docker.host.query')
    yield AttachRPC('containers-query', 'docker.container.query')
    yield AttachRPC('networks-query', 'docker.network.query')
    yield AttachRPC('images-query', 'docker.image.query')
    yield AttachRPC('collections-query', 'docker.collection.query')
    yield AttachRPC('containerd-containers', CONTAINERS_QUERY)
    yield AttachRPC('containerd-networks', NETWORKS_QUERY)
    yield AttachRPC('containerd-images', IMAGES_QUERY)


def _depends():
    return ['VMPlugin', 'VolumePlugin']


def _init(dispatcher, plugin):
    global collections
    global images
    global containers_state
    global containers_rename_cache
    global hosts_status_cache
    global containers_lock
    global networks_lock
    global images_lock

    containers_lock = RLock()
    networks_lock = RLock()
    images_lock = RLock()

    images = EventCacheStore(dispatcher, 'docker.image')
    collections = CacheStore()
    containers_state = CacheStore()
    containers_rename_cache = CacheStore()
    hosts_status_cache = CacheStore()

    def on_host_event(args):
        if args['operation'] == 'create':
            for host_id in args['ids']:
                refresh_cache(dispatcher, host_id=host_id)
                logger.debug('Docker host {0} started'.format(host_id))

        elif args['operation'] == 'delete':
            for host_id in args['ids']:
                logger.debug('Docker host {0} stopped'.format(host_id))

        dispatcher.dispatch_event('docker.host.changed', {
            'operation': 'update',
            'ids': args['ids']
        })

    def vm_pre_destroy(args):
        host = dispatcher.datastore.query(
            'vms',
            ('config.docker_host', '=', True),
            ('id', '=', args['name']),
            single=True
        )
        if host:
            logger.debug('Docker host {0} deleted'.format(host['name']))
            dispatcher.dispatch_event('docker.host.changed', {
                'operation': 'delete',
                'ids': [args['name']]
            })

    def on_vm_change(args):
        if args['operation'] == 'create':
            for id in args['ids']:
                host = dispatcher.datastore.query(
                    'vms',
                    ('config.docker_host', '=', True),
                    ('id', '=', id),
                    single=True
                )
                if host:
                    logger.debug('Docker host {0} created'.format(host['name']))

                    default_host = dispatcher.call_sync('docker.config.get_config').get('default_host')
                    if not default_host:
                        dispatcher.call_task_sync('docker.config.update', {'default_host': host['id']})
                        logger.info('Docker host {0} set automatically as default Docker host'.format(host['name']))

                    dispatcher.dispatch_event('docker.host.changed', {
                        'operation': 'create',
                        'ids': [id]
                    })

        elif args['operation'] == 'delete':
            for id in args['ids']:
                refresh_cache(dispatcher, host_id=id)

            if dispatcher.call_sync('docker.config.get_config').get('default_host') in args['ids']:
                host = dispatcher.datastore.query(
                    'vms',
                    ('config.docker_host', '=', True),
                    single=True,
                )

                if host:
                    logger.info(
                        'Old default host deleted. Docker host {0} set automatically as default Docker host'.format(
                            host['name']
                        )
                    )
                    host_id = host['id']
                else:
                    logger.info(
                        'Old default host deleted. There are no Docker hosts left to take the role of default host.'
                    )
                    host_id = None

                dispatcher.call_task_sync('docker.config.update', {'default_host': host_id})

        elif args['operation'] == 'update':
            for id in args['ids']:
                host = dispatcher.call_sync(
                    'vm.query',
                    [('config.docker_host', '=', True), ('id', '=', id)],
                    {'single': True}
                )
                if host:
                    dispatcher.dispatch_event('docker.host.changed', {
                        'operation': 'update',
                        'ids': [id]
                    })

                    if q.get(host, 'status.state') == 'RUNNING':
                        refresh_cache(dispatcher, host_id=id)
                        try:
                            hosts_status_cache.put(
                                id,
                                dispatcher.call_sync('containerd.docker.get_host_status', id, timeout=100)
                            )
                            dispatcher.dispatch_event('docker.host.changed', {
                                'operation': 'update',
                                'ids': [id]
                            })
                        except RpcException:
                            hosts_status_cache.remove(id)

                    else:
                        hosts_status_cache.remove(id)
                        containers = dispatcher.datastore_log.query(
                            'docker.containers',
                            ('host', '=', id),
                            select='id'
                        )

                        if containers:
                            containers_state.remove_many(containers)
                            dispatcher.dispatch_event('docker.container.changed', {
                                'operation': 'update',
                                'ids': containers
                            })

                        networks = dispatcher.datastore_log.query(
                            'docker.networks',
                            ('host', '=', id),
                            select='id'
                        )
                        if networks:
                            dispatcher.dispatch_event('docker.network.changed', {
                                'operation': 'update',
                                'ids': networks
                            })

    def on_image_event(args):
        with images_lock:
            logger.debug('Received Docker image event: {0}'.format(args))
            if args['ids']:
                if args['operation'] == 'delete':
                    images.remove_many(args['ids'])
                else:
                    sync_images(dispatcher, args['ids'])

    def on_container_event(args):
        logger.debug('Received Docker container event: {0}'.format(args))
        if args['ids']:
            with containers_lock:
                for id in args['ids']:
                    if args['operation'] in ('create', 'update'):
                        state = list(dispatcher.call_sync(
                            CONTAINERS_QUERY,
                            [('id', '=', id)],
                            {'select': ('running', 'health')}
                        ))
                        if state:
                            status = {
                                'running': bool(state[0][0]),
                                'health': state[0][1]
                            }
                            containers_state.put(id, status)
                    else:
                        containers_state.remove(id)

                refresh_containers(dispatcher, ids=args['ids'])

    def on_network_event(args):
        logger.debug('Received Docker network event: {}'.format(args))
        if args['ids']:
            with networks_lock:
                refresh_networks(dispatcher, ids=args['ids'])

    plugin.register_provider('docker.config', DockerConfigProvider)
    plugin.register_provider('docker.host', DockerHostProvider)
    plugin.register_provider('docker.container', DockerContainerProvider)
    plugin.register_provider('docker.network', DockerNetworkProvider)
    plugin.register_provider('docker.image', DockerImagesProvider)
    plugin.register_provider('docker.collection', DockerCollectionProvider)

    plugin.register_task_handler('docker.config.update', DockerUpdateTask)

    plugin.register_task_handler('docker.container.create', DockerContainerCreateTask)
    plugin.register_task_handler('docker.container.update', DockerContainerUpdateTask)
    plugin.register_task_handler('docker.container.delete', DockerContainerDeleteTask)
    plugin.register_task_handler('docker.container.start', DockerContainerStartTask)
    plugin.register_task_handler('docker.container.stop', DockerContainerStopTask)
    plugin.register_task_handler('docker.container.restart', DockerContainerRestartTask)
    plugin.register_task_handler('docker.container.clone', DockerContainerCloneTask)
    plugin.register_task_handler('docker.container.commit', DockerContainerCommitTask)

    plugin.register_task_handler('docker.network.create', DockerNetworkCreateTask)
    plugin.register_task_handler('docker.network.update', DockerNetworkUpdateTask)
    plugin.register_task_handler('docker.network.delete', DockerNetworkDeleteTask)
    plugin.register_task_handler('docker.network.connect', DockerNetworkConnectTask)
    plugin.register_task_handler('docker.network.disconnect', DockerNetworkDisconnectTask)

    plugin.register_task_handler('docker.image.pull', DockerImagePullTask)
    plugin.register_task_handler('docker.image.delete', DockerImageDeleteTask)
    plugin.register_task_handler('docker.image.flush', DockerImageFlushTask)

    plugin.register_task_handler('docker.host.create', DockerHostCreateTask)
    plugin.register_task_handler('docker.host.update', DockerHostUpdateTask)
    plugin.register_task_handler('docker.host.delete', DockerHostDeleteTask)

    plugin.register_task_handler('docker.collection.create', DockerCollectionCreateTask)
    plugin.register_task_handler('docker.collection.update', DockerCollectionUpdateTask)
    plugin.register_task_handler('docker.collection.delete', DockerCollectionDeleteTask)
    plugin.register_task_handler('docker.collection.get_presets', DockerCollectionGetPresetsTask)

    plugin.register_event_type('docker.host.changed')
    plugin.register_event_type('docker.config.changed')
    plugin.register_event_type('docker.container.changed')
    plugin.register_event_type('docker.network.changed')
    plugin.register_event_type('docker.image.changed')
    plugin.register_event_type('docker.collection.changed')

    plugin.register_event_handler('containerd.docker.host.changed', on_host_event)
    plugin.register_event_handler('containerd.docker.container.changed', on_container_event)
    plugin.register_event_handler('containerd.docker.network.changed', on_network_event)
    plugin.register_event_handler('containerd.docker.image.changed', on_image_event)
    plugin.register_event_handler('vm.changed', on_vm_change)
    plugin.register_event_handler(
        'plugin.service_registered',
        lambda a: refresh_cache(dispatcher) if a['service-name'] == 'containerd.docker' else None
    )

    plugin.attach_hook('vm.pre_destroy', vm_pre_destroy)

    dispatcher.register_resource(Resource('docker'), parents=['root'])

    plugin.register_debug_hook(collect_debug)

    plugin.register_schema_definition('DockerConfig', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'default_host': {'type': ['string', 'null']},
            'api_forwarding': {'type': ['string', 'null']},
            'api_forwarding_enable': {'type': 'boolean'}
        }
    })

    plugin.register_schema_definition('DockerCollection', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'status': {'$ref': 'DockerCollectionStatus'},
            'name': {'type': 'string'},
            'collection': {'type': 'string'},
            'match_expr': {'type': ['string', 'null']},
            'images': {'$ref': 'DockerHubImage'}
        }
    })

    plugin.register_schema_definition('DockerCollectionStatus', {
        'type': 'string',
        'enum': ['OK', 'ERROR', 'UNKNOWN'],
        'readOnly': True
    })

    plugin.register_schema_definition('DockerHost', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'state': {'$ref': 'DockerHostState'},
            'target': {'type': 'string'},
            'config': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'memsize': {'type': 'integer'},
                    'ncpus': {'type': 'integer'}
                }
            },
            'status': {
                'oneOf': [{'$ref': 'DockerHostStatus'}, {'type': 'null'}]
            }
        }
    })

    plugin.register_schema_definition('DockerHostState', {
        'type': 'string',
        'enum': ['UP', 'CONNECTING', 'DOWN']
    })

    plugin.register_schema_definition('DockerHostStatus', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'unique_id': {'type': 'string'},
            'hostname': {'type': 'string'},
            'os': {'type': 'string'},
            'mem_total': {'type': 'integer'}
        }
    })

    plugin.register_schema_definition('DockerContainer', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'names': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'pattern': docker_names_pattern
                }
            },
            'command': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'image': {'type': 'string'},
            'image_id': {'type': 'string', 'readOnly': True},
            'host': {'type': ['string', 'null']},
            'hostname': {'type': ['string', 'null']},
            'memory_limit': {'type': ['integer', 'null']},
            'expose_ports': {'type': 'boolean'},
            'autostart': {'type': 'boolean'},
            'running': {'type': 'boolean', 'readOnly': True},
            'health': {'type': ['string', 'null'], 'readOnly': True},
            'reachable': {'type': 'boolean', 'readOnly': True},
            'interactive': {'type': 'boolean'},
            'version': {'type': 'string', 'readOnly': True},
            'web_ui_url': {'type': 'string', 'readOnly': True},
            'hub_url': {'type': 'string', 'readOnly': True},
            'environment': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'exec_ids': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'settings': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'id': {'type': 'string'},
                        'value': {'type': ['string', 'integer', 'boolean', 'null']}
                    }
                }
            },
            'ports': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'protocol': {'$ref': 'DockerPortProtocol'},
                        'container_port': {
                            'type': 'integer',
                            'minimum': 0,
                            'maximum': 65535
                        },
                        'host_port': {
                            'type': 'integer',
                            'minimum': 0,
                            'maximum': 65535
                        }
                    }
                }
            },
            'volumes': {
                'type': 'array',
                'items': {'$ref': 'DockerVolume'}
            },
            'bridge': {'$ref': 'DockerContainerBridge'},
            'parent_directory': {'type': 'string'},
            'capabilities_add': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'capabilities_drop': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'privileged': {'type': 'boolean'},
            'primary_network_mode': {'oneOf': [{'$ref': 'DockerContainerNetworkMode'}, {'type': 'null'}]},
            'networks': {
                'type': 'array',
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('DockerContainerNetworkMode', {
        'type': 'string',
        'enum': ['NAT', 'BRIDGED', 'HOST', 'NONE']
    })

    plugin.register_schema_definition('DockerContainerBridge', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'dhcp': {'type': 'boolean'},
            'address': {'type': ['string', 'null']},
            'macaddress': {'type': ['string', 'null']}
        }
    })

    plugin.register_schema_definition('DockerNetwork', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {
                'type': 'string',
                'pattern': docker_names_pattern
            },
            'host': {'type': ['string', 'null']},
            'driver': {'type': ['string', 'null']},
            'subnet': {'type': ['string', 'null']},
            'gateway': {'type': ['string', 'null']},
            'containers': {
                'type': 'array',
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('DockerImage', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'names': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'size': {'type': 'integer'},
            'parent': {'type': 'string'},
            'hosts': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'presets': {'type': ['object', 'null']},
            'version': {'type': 'string'},
            'created_at': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('DockerHubImage', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'name': {'type': 'string'},
            'description': {'type': 'string'},
            'icon': {'type': 'string'},
            'pull_count': {'type': 'integer'},
            'star_count': {'type': 'integer'},
            'version': {'type': 'string'},
            'presets': {'type': ['object', 'null']}
        }
    })

    plugin.register_schema_definition('DockerVolume', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'container_path': {'type': 'string'},
            'host_path': {'type': 'string'},
            'readonly': {'type': 'boolean'},
            'source': {'$ref': 'DockerVolumeHostPathSource'}
        }
    })

    plugin.register_schema_definition('DockerPortProtocol', {
        'type': 'string',
        'enum': ['TCP', 'UDP']
    })

    plugin.register_schema_definition('DockerVolumeHostPathSource', {
        'type': 'string',
        'enum': ['HOST', 'VM']
    })

    if 'containerd.docker' in dispatcher.call_sync('discovery.get_services'):
        refresh_cache(dispatcher)

    if not dispatcher.call_sync('docker.config.get_config').get('default_host'):
        host_id = dispatcher.datastore.query(
            'vms',
            ('config.docker_host', '=', True),
            single=True,
            select='id'
        )
        if host_id:
            dispatcher.call_task_sync('docker.config.update', {'default_host': host_id})

    dispatcher.track_resources(
        'docker.host.query',
        'entity-subscriber.docker.host.changed',
        lambda id: f'docker:{id}',
        lambda host: ['docker', f'volume:{host["target"]}']
    )
