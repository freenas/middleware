# +
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

import errno
import gevent
import logging
import os
import sys
import re
import tarfile
import shutil
from freenas.utils import human_readable_bytes
from freenas.utils.decorators import throttle
from resources import Resource
from cache import CacheStore
from freenas.dispatcher.rpc import (
    RpcException, description, accepts, returns, private, SchemaHelper as h
)
from task import (
    Provider, Task, ProgressTask, TaskException, TaskDescription,
    VerifyException, TaskWarning
)

if '/usr/local/lib' not in sys.path:
    sys.path.append('/usr/local/lib')
from freenasOS import Configuration, Train, Manifest, disable_trygetfilelogs
from freenasOS.Exceptions import (
    UpdateManifestNotFound, ManifestInvalidSignature, UpdateBootEnvironmentException,
    UpdatePackageException, UpdateIncompleteCacheException, UpdateBusyCacheException,
    ChecksumFailException, UpdatePackageNotFound
)
from freenasOS.Update import CheckForUpdates, DownloadUpdate, ApplyUpdate, Avatar

# The function calls below help reduce the debug logs
# removing unnecessary 'TryGetNetworkFile' and such logs
# thereby not inundating /var/log/dispatcher.log
disable_trygetfilelogs()

logger = logging.getLogger('UpdatePlugin')
update_cache = CacheStore()
default_update_dict = {
    'available': False,
    'operations': None,
    'notes': None,
    'notice': None,
    'downloaded': False,
    'changelog': '',
    'version': '',
    'installed': False,
    'installed_version': ''
}

update_resource_string = 'update:operations'


UPDATE_ALERT_TITLE_MAP = {
    'UpdateAvailable': 'Update Available',
    'UpdateDownloaded': 'Update Downloaded',
    'UpdateInstalled': 'Update Installed'
}


def parse_changelog(changelog, start='', end=''):
    "Utility function to parse an available changelog"
    regexp = r'### START (\S+)(.+?)### END \1'
    reg = re.findall(regexp, changelog, re.S | re.M)

    if not reg:
        return None

    changelog = None
    for seq, changes in reg:
        if not changes.strip('\n'):
            continue
        if seq == start:
            # Once we found the right one, we start accumulating
            changelog = []
        elif changelog is not None:
            changelog.append(changes.strip('\n'))
        if seq == end:
            break
    aggregated_changelog = []
    try:
        for x in changelog:
            aggregated_changelog.extend(x.split('\n'))
    except Exception:
        # a traceback here is not worth taking the whole update task with it
        # hence the bare except
        pass
    return aggregated_changelog or ['']


def get_changelog(train, cache_dir='/var/tmp/update', start='', end=''):
    "Utility to get and eventually parse a changelog if available"
    conf = Configuration.Configuration()
    changelog = None
    try:
        changelog = conf.GetChangeLog(train=train, save_dir=cache_dir)
        if not changelog:
            return None
        return parse_changelog(changelog.read().decode('utf8'), start, end)
    finally:
        if changelog:
            changelog.close()


# The handler(s) below is/are taken from the freenas 9.3 code
# specifically from gui/system/utils.py
class CheckUpdateHandler(object):
    "A handler for the CheckUpdate call"

    def __init__(self):
        self.changes = []

    def call(self, op, newpkg, oldpkg):
        self.changes.append({
            'operation': op,
            'old': oldpkg,
            'new': newpkg,
        })

    def output(self):
        output = []
        for c in self.changes:
            opdict = {
                'operation': c['operation'],
                'previous_name': c['old'].Name() if c['old'] else None,
                'previous_version': c['old'].Version() if c['old'] else None,
                'new_name': c['new'].Name() if c['new'] else None,
                'new_version': c['new'].Version() if c['new'] else None,
            }
            output.append(opdict)
        return output


def is_update_applied(dispatcher, update_version):
    # TODO: The below boot env name should really be obtained from the update code
    # for now we just duplicate that code here
    if update_version.startswith(Avatar() + "-"):
        update_boot_env = update_version[len(Avatar() + "-"):]
    else:
        update_boot_env = "%s-%s" % (Avatar(), update_version)

    return dispatcher.call_sync(
        'boot.environment.query', [('realname', '=', update_boot_env)], {"single": True}
    )


def check_updates(dispatcher, configstore, cache_dir=None, check_now=False):
    """
    Utility function to just check for Updates
    """
    update_cache_value_dict = default_update_dict.copy()

    # If the current check is an online one (and not in the cache_dir)
    # then store the current update info and use them to restore the update cache
    # if the update check fails, this way a downloaded update is not lost from
    # the cache if a live online one fails!
    current_update_info = None
    try:
        current_update_info = dispatcher.call_sync('update.update_info')
        if (
            current_update_info.get('installed') and
            is_update_applied(dispatcher, current_update_info.get('installed_version'))
        ):
            update_cache_value_dict.update({
                'installed': True,
                'installed_version': current_update_info.get('installed_version')
            })

        if check_now and current_update_info['downloaded']:
            update_cache_value_dict.update(current_update_info.copy())
            update_cache_value_dict['available'] = True
    except RpcException:
        pass

    logger.trace('check_updates: this is the current_update_info: {0}'.format(current_update_info))
    dispatcher.call_sync('update.update_cache_invalidate', list(update_cache_value_dict.keys()))

    conf = Configuration.Configuration()
    handler = CheckUpdateHandler()
    train = configstore.get('update.train')

    logger.trace(
        'check_updates: Update server name: {0}, url: {1}'.format(
            conf.UpdateServerName(), conf.UpdateServerURL())
    )

    try:
        update = CheckForUpdates(
            handler=handler.call,
            train=train,
            cache_dir=None if check_now else cache_dir,
        )

        if update:
            version = update.Version()
            update_installed_bootenv = is_update_applied(dispatcher, version)
            sys_mani = conf.SystemManifest()
            sequence = sys_mani.Sequence() if sys_mani else ''
            if version == update_cache_value_dict['installed_version'] or update_installed_bootenv:
                if update_installed_bootenv and update_installed_bootenv['active']:
                    # it could be possible that the installed os has the same version as
                    # the one available from the server and yet the one on the server has
                    # something new to offer, hence check for seequence numbers to rule out
                    # all doubt
                    if update.Sequence() == sequence:
                        logger.debug('Update has same sequence number as current OS')
                        # At this point clear any installed version stuff
                        update_cache_value_dict.update({
                            'installed': False,
                            'installed_version': ''
                        })
                    else:
                        logger.debug(
                            'Update has same version but different sequence number as current OS'
                        )
                else:
                    # TODO: mount the BE in question to inspect sequence number
                    logger.debug(
                        'Update version {0} is already installed in BE {1}'.format(
                            version, update_installed_bootenv
                        )
                    )
                    update_cache_value_dict = default_update_dict.copy()
                    update_cache_value_dict.update({
                        'installed': True,
                        'installed_version': version
                    })
                    dispatcher.call_sync(
                        'update.update_alert_set',
                        'UpdateInstalled',
                        version,
                        {'update_installed_bootenv': update_installed_bootenv}
                    )
            else:
                logger.debug('Update {0} is available'.format(version))
                try:
                    if check_now:
                        changelog = get_changelog(
                            train, cache_dir=cache_dir, start=sequence, end=update.Sequence()
                        )
                    else:
                        with open("{0}/ChangeLog.txt".format(cache_dir), 'r') as changelog_file:
                            changelog = parse_changelog(
                                changelog_file.read(), start=sequence, end=update.Sequence()
                            )
                except Exception:
                    changelog = ''
                update_cache_value_dict.update({
                    'available': True,
                    'notes': update.Notes(),
                    'notice': update.Notice(),
                    'operations': handler.output(),
                    'version': version,
                    'changelog': changelog,
                    'downloaded': False if check_now else True
                })

                dispatcher.call_sync(
                    'update.update_alert_set',
                    'UpdateDownloaded' if update_cache_value_dict['downloaded'] else 'UpdateAvailable',
                    update_cache_value_dict['version']
                )

        else:
            logger.debug('No update available')
    finally:
        dispatcher.call_sync('update.update_cache_putter', update_cache_value_dict)


class UpdateHandler(object):
    "A handler for Downloading and Applying Updates calls"

    def __init__(self, dispatcher, update_progress=None):
        self.progress = 0
        self.details = ''
        self.finished = False
        self.error = False
        self.indeterminate = False
        self.reboot = False
        self.pkgname = ''
        self.pkgversion = ''
        self.operation = ''
        self._baseprogress = 0
        self.master_progress = 0
        self.pkgindex = 0
        self.numpkgs = 0
        self.dispatcher = dispatcher
        # Below is the function handle passed to this by the Task so that
        # its status and progress can be updated accordingly
        self.update_progress = update_progress

    def check_handler(self, index, pkg, pkgList):
        self.pkgname = pkg.Name()
        self.pkgversion = pkg.Version()
        self.operation = 'Downloading'
        self.details = 'Downloading {0}'.format(self.pkgname)
        stepprogress = int((1.0 / float(len(pkgList))) * 100)
        self._baseprogress = index * stepprogress
        self.progress = (index - 1) * stepprogress
        # self.emit_update_details()

    def get_handler(self, method, filename, size=None, progress=None, download_rate=None):
        if progress is not None:
            self.progress = (progress * self._baseprogress) / 100
            if self.progress == 0:
                self.progress = 1
            display_size = ' Size: {0} '.format(human_readable_bytes(size)) if size else ''
            display_rate = ' Rate: {0} '.format(human_readable_bytes(download_rate, suffix='/s')) if download_rate else ''
            self.details = 'Downloading: {0} Progress:{1}{2}{3}'.format(
                self.pkgname, progress, display_size, display_rate
            )
        self.emit_update_details()

    def install_handler(self, index, name, packages):
        self.indeterminate = False
        self.numpkgs = len(packages)
        self.pkgindex = index
        self.pkgname = name
        self.progress = self._baseprogress = int((self.pkgindex - 1) * 100 / self.numpkgs)
        self.operation = 'Installing'
        self.details = 'Installing {0}'.format(self.pkgname)
        self.emit_update_details()

    def install_progress_handler(self, **kwargs):
        total = kwargs.pop("total", 0)
        index = kwargs.pop("index", 0)
        done = kwargs.pop("done", False)

        if done:
            self.progress = int(self.pkgindex * 100 / self.numpkgs)
            self.details = 'Done installing {0}'.format(self.pkgname)
        elif total:
            cur_pct = int(index * 100 / (total * self.numpkgs))
            self.details = 'Installing {0} Progress: {1}'.format(
                self.pkgname, self.numpkgs * cur_pct
            )
            if (self._baseprogress + cur_pct) > self.progress:
                self.progress = self._baseprogress + cur_pct

        self.emit_update_details()

    @throttle(seconds=1)
    def emit_update_details(self):
        # Doing the drill below as there is a small window when
        # step*progress logic does not catch up with the new value of step
        if self.progress >= self.master_progress:
            self.master_progress = self.progress
        data = {
            'indeterminate': self.indeterminate,
            'percent': self.master_progress,
            'reboot': self.reboot,
            'pkg_name': self.pkgname,
            'pkg_version': self.pkgversion,
            'error': self.error,
            'finished': self.finished,
            'details': self.details,
        }
        if self.update_progress is not None:
            self.update_progress(self.master_progress, self.details)
        self.dispatcher.dispatch_event('update.in_progress', {
            'operation': self.operation,
            'data': data,
        })


def generate_update_cache(dispatcher, cache_dir=None):
    if cache_dir is None:
        try:
            cache_dir = dispatcher.call_sync('system_dataset.request_directory', 'update')
        except RpcException:
            cache_dir = '/var/tmp/update'
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
    update_cache.put('cache_dir', cache_dir)
    try:
        check_updates(dispatcher, dispatcher.configstore, cache_dir=cache_dir)
    except:
        # What to do now?
        logger.debug('generate_update_cache (UpdatePlugin) falied, traceback: ', exc_info=True)


@description("Provides System Updater Configuration")
class UpdateProvider(Provider):

    @accepts()
    @returns(str)
    def is_update_available(self):
        temp_available = update_cache.get('available', timeout=1)
        if temp_available is not None:
            return temp_available
        elif update_cache.is_valid('available'):
            return temp_available
        else:
            raise RpcException(errno.EBUSY, (
                'Update Availability flag is invalidated, an Update Check'
                ' might be underway. Try again in some time.'
            ))

    @accepts()
    @returns(h.array(str))
    def obtain_changelog(self):
        temp_changelog = update_cache.get('changelog', timeout=1)
        if temp_changelog is not None:
            return temp_changelog
        elif update_cache.is_valid('changelog'):
            return temp_changelog
        else:
            raise RpcException(errno.EBUSY, (
                'Changelog list is invalidated, an Update Check '
                'might be underway. Try again in some time.'
            ))

    @accepts()
    @returns(h.array(h.ref('UpdateOps')))
    def get_update_ops(self):
        temp_operations = update_cache.get('operations', timeout=1)
        if temp_operations is not None:
            return temp_operations
        elif update_cache.is_valid('operations'):
            return temp_operations
        else:
            raise RpcException(errno.EBUSY, (
                'Update Operations Dict is invalidated, an Update Check '
                'might be underway. Try again in some time.'
            ))

    @accepts()
    @returns(h.ref('UpdateInfo'))
    def update_info(self):
        if not update_cache.is_valid('available'):
            raise RpcException(errno.EBUSY, (
                'Update Availability flag is invalidated, an Update Check'
                ' might be underway. Try again in some time.'
            ))
        info_item_list = [
            'available', 'changelog', 'notes', 'notice', 'operations', 'downloaded',
            'version', 'installed', 'installed_version'
        ]
        return {key: update_cache.get(key, timeout=1) for key in info_item_list}

    @returns(h.any_of(
        h.array(h.ref('UpdateTrain')),
        None,
    ))
    def trains(self):
        conf = Configuration.Configuration()
        conf.LoadTrainsConfig()
        trains = conf.AvailableTrains()

        if trains is None:
            logger.debug('The AvailableTrains call returned None. Check your network connection')
            return None
        seltrain = self.dispatcher.configstore.get('update.train')

        data = []
        for name in list(trains.keys()):
            if name in conf._trains:
                train = conf._trains.get(name)
            else:
                train = Train.Train(name)
            data.append({
                'name': train.Name(),
                'description': train.Description(),
                'sequence': train.LastSequence(),
                'current': True if name == seltrain else False,
            })
        return data

    @accepts()
    @returns(str)
    def get_current_train(self):
        conf = Configuration.Configuration()
        conf.LoadTrainsConfig()
        return conf.CurrentTrain()

    @accepts()
    @returns(h.ref('Update'))
    def get_config(self):
        configuration = Configuration.Configuration()
        return {
            'train': self.dispatcher.configstore.get('update.train'),
            'check_auto': self.dispatcher.configstore.get('update.check_auto'),
            'internal': configuration.UpdateServerName() == 'internal',
            'update_server': configuration.UpdateServerURL(),
        }

    @private
    @accepts(h.array(str))
    def update_cache_invalidate(self, value_list):
        for item in value_list:
            update_cache.invalidate(item)

    @private
    @accepts(h.object())
    def update_cache_putter(self, value_dict):
        for key, value in value_dict.items():
            update_cache.put(key, value)
        self.dispatcher.dispatch_event('update.update_info.updated', {'operation': 'update'})

    @private
    @accepts(str)
    @returns(h.any_of(None, str, bool, h.array(str)))
    def update_cache_getter(self, key):
        return update_cache.get(key, timeout=1)

    @private
    @accepts(str, str, h.any_of(None, h.object(additionalProperties=True)))
    def update_alert_set(self, update_class, update_version, kwargs=None):
        # Formulating a query to find any alerts in the current `update_class`
        # which could be either of ('UpdateAvailable', 'UpdateDownloaded', 'UpdateInstalled')
        # as well as any alerts for the specified update version string.
        # The reason I do this is because say an Update is Downloaded (FreeNAS-10-2016051047)
        # and there is either a previous alert for an older downloaded update OR there is a
        # previous alert for the same version itself but for it being available instead of being
        # downloaded already, both of these previous alerts would need to be cancelled and
        # replaced by 'UpdateDownloaded' for FreeNAS-10-2016051047.
        if kwargs is None:
            kwargs = {}
        existing_update_alerts = self.dispatcher.call_sync(
            'alert.query',
            [
                ('and', [('active', '=', True), ('dismissed', '=', False)]),
                ('or', [('clazz', '=', update_class), ('target', '=', update_version)])
            ]
        )
        title = UPDATE_ALERT_TITLE_MAP.get(update_class, 'Update Alert')
        desc = kwargs.get('desc')
        if desc is None:
            if update_class == 'UpdateAvailable':
                desc = 'Latest Update: {0} is available for download'.format(update_version)
            elif update_class == 'UpdateDownloaded':
                desc = 'Update containing {0} is downloaded and ready for install'.format(update_version)
            elif update_class == 'UpdateInstalled':
                update_installed_bootenv = kwargs.get('update_installed_bootenv')
                if update_installed_bootenv and not update_installed_bootenv['on_reboot']:
                    desc = 'Update containing {0} is installed.'.format(update_version)
                    desc += ' Please activate {0} and Reboot to use this updated version'.format(update_installed_bootenv['realname'])
                else:
                    desc = 'Update containing {0} is installed and activated for next boot'.format(update_version)
            else:
                # what state is this?
                raise RpcException(
                    errno.EINVAL, 'Unknown update alert class: {0}'.format(update_class)
                )
        alert_payload = {
            'clazz': update_class,
            'title': title,
            'target': update_version,
            'description': desc
        }

        alert_exists = False
        # Purposely deleting stale alerts later on since if anything (in constructing the payload)
        # above this fails the exception prevents alert.cancel from being called.
        for update_alert in existing_update_alerts:
            if (
                update_alert['clazz'] == update_class and
                update_alert["target"] == update_version and
                update_alert["description"] == desc
            ):
                alert_exists = True
                continue
            self.dispatcher.call_sync('alert.cancel', update_alert['id'])

        if not alert_exists:
            self.dispatcher.call_sync('alert.emit', alert_payload)


@description("Set the System Updater Cofiguration Settings")
@accepts(h.ref('Update'))
class UpdateConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return "Configuring updates"

    def describe(self, props):
        return TaskDescription("Configuring updates")

    def verify(self, props):
        # TODO: Fix this verify's resource allocation as unique task
        block = self.dispatcher.resource_graph.get_resource(update_resource_string)
        if block is not None and block.busy:
            raise VerifyException(
                errno.EBUSY,
                'An update operation (Configuration/Downloading/Applying ' +
                'the updates) is already in the queue; please retry later')

        return [update_resource_string]

    def run(self, props):
        if 'train' in props:
            train_to_set = props.get('train')
            conf = Configuration.Configuration()
            conf.LoadTrainsConfig()
            trains = conf.AvailableTrains() or []
            if trains:
                trains = list(trains.keys())
            if train_to_set not in trains:
                raise TaskException(errno.ENOENT, '{0} is not a valid train'.format(train_to_set))
            self.configstore.set('update.train', train_to_set)

        if 'check_auto' in props:
            self.configstore.set('update.check_auto', props['check_auto'])

        if 'internal' in props:
            conf = Configuration.SystemConfiguration()
            if 'internal' not in conf.ListUpdateServers():
                conf.AddUpdateServer(Configuration.UpdateServer(
                    'internal',
                    'http://update-int.ixsystems.com/FreeNAS/',
                    signing=False
                ))

            conf.SetUpdateServer('internal' if props['internal'] else 'default')

        cache_dir = self.dispatcher.call_sync('update.update_cache_getter', 'cache_dir')
        check_updates(self.dispatcher, self.configstore, cache_dir=cache_dir, check_now=True)

        self.dispatcher.dispatch_event('update.changed', {'operation': 'update'})


@description(
    "Checks for Available Updates and returns if update is available "
    "and if yes returns information on operations that will be "
    "performed during the update"
)
@accepts(h.object(properties={'check_now': bool}))
class CheckUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Checking for updates"

    def describe(self, conditions=None):
        return TaskDescription("Checking for updates")

    def verify(self, conditions=None):
        # TODO: Fix this verify's resource allocation as unique task
        block = self.dispatcher.resource_graph.get_resource(update_resource_string)
        if block is not None and block.busy:
            raise VerifyException(errno.EBUSY, (
                'An update operation (Configuration/Downloading/Applying '
                'the updates) is already in the queue; please retry later'
            ))

        return [update_resource_string]

    def run(self, conditions=None):
        if conditions is None:
            conditions = {}

        check_now = conditions.get('check_now', True)
        cache_dir = self.dispatcher.call_sync('update.update_cache_getter', 'cache_dir')
        try:
            check_updates(
                self.dispatcher, self.configstore, cache_dir=cache_dir, check_now=check_now
            )
        except UpdateManifestNotFound:
            raise TaskException(errno.ENETUNREACH, 'Update server could not be reached')
        except Exception as e:
            raise TaskException(errno.EAGAIN, '{0}'.format(str(e)))


@description("Downloads Updates for the current system update train")
@accepts()
class DownloadUpdateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Downloading updates"

    def describe(self):
        return TaskDescription("Downloading updates")

    def verify(self):
        if not update_cache.get('available', timeout=1):
            raise VerifyException(errno.ENOENT, (
                'No updates currently available for download - check for new updates'
            ))

        block = self.dispatcher.resource_graph.get_resource(update_resource_string)
        if block is not None and block.busy:
            raise VerifyException(errno.EBUSY, (
                'An update operation (Configuration/Downloading/Applying '
                'the updates) is already in the queue; please retry later'
            ))

        return [update_resource_string]

    def update_progress(self, progress, message):
        self.set_progress(progress, message)

    def run(self):
        self.set_progress(0, 'Downloading Updates...')
        handler = UpdateHandler(self.dispatcher, update_progress=self.update_progress)
        train = self.configstore.get('update.train')
        cache_dir = self.dispatcher.call_sync('update.update_cache_getter', 'cache_dir')
        if cache_dir is None:
            try:
                cache_dir = self.dispatcher.call_sync(
                    'system_dataset.request_directory', 'update'
                )
            except RpcException:
                cache_dir = '/var/tmp/update'
        try:
            download_successful = DownloadUpdate(
                train,
                cache_dir,
                get_handler=handler.get_handler,
                check_handler=handler.check_handler
            )
        except ManifestInvalidSignature as e:
            raise TaskException(
                errno.EBADMSG, 'Latest manifest has invalid signature: {0}'.format(str(e))
            )
        except UpdateIncompleteCacheException as e:
            raise TaskException(errno.EIO, 'Possibly with no network, cached update is incomplete')
        except UpdateBusyCacheException as e:
            raise TaskException(errno.EBUSY, str(e))
        except ChecksumFailException as e:
            raise TaskException(errno.EBADMSG, str(e))
        except UpdatePackageNotFound as e:
            raise TaskException(
                errno.EIO,
                "Update Package: '{0}' Not Found. This could be due to a failed Download".format(str(e))
            )
        except Exception as e:
            raise TaskException(
                errno.EAGAIN, 'Got exception {0} while trying to Download Updates'.format(str(e))
            )
        if not download_successful:
            handler.error = True
            handler.emit_update_details()
            raise TaskException(
                errno.EAGAIN, 'Downloading Updates Failed for some reason, check logs'
            )
        check_updates(self.dispatcher, self.configstore, cache_dir=cache_dir, check_now=False)
        handler.finished = True
        handler.emit_update_details()
        self.set_progress(100, 'Updates finished downloading')


@description("Apply a manual update using specified tarfile")
@accepts(str, h.one_of(bool, None))
class UpdateManualTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Updating via the provided update tarfile'

    def describe(self, path, reboot_post_install=False):
        return TaskDescription("Updating from tarfile ({name})".format(name=path))

    def verify(self, path, reboot_post_install=False):

        if not os.path.exists(path):
            raise VerifyException(errno.EEXIST, 'File does not exist')

        if not tarfile.is_tarfile(path):
            raise VerifyException(errno.EEXIST, 'File does not exist')

        return ['root']

    def run(self, path, reboot_post_install=False):
        self.set_progress(0, 'Extracting update from tarfile...')

        cache_dir = self.dispatcher.call_sync('update.update_cache_getter', 'cache_dir')
        if cache_dir is None:
            try:
                cache_dir = self.dispatcher.call_sync(
                    'system_dataset.request_directory', 'update'
                )
            except RpcException:
                cache_dir = '/var/tmp/update'
        # Frozen tarball.  We'll extract it into the cache directory, and
        # then add a couple of things to make it pass sanity, and then apply it.
        # For now we just copy the code above.
        # First, remove the cache directory
        # Hrm, could overstep a locked file.
        shutil.rmtree(cache_dir, ignore_errors=True)
        try:
            os.makedirs(cache_dir)
        except BaseException as e:
            raise TaskException(
                errno.EPERM,
                "Unable to create cache directory {0}: {1}".format(cache_dir, str(e))
            )

        try:
            with tarfile.open(path) as tf:
                files = tf.getmembers()
                for f in files:
                    if f.name in ("./", ".", "./."):
                        continue
                    if not f.name.startswith("./"):
                        continue
                    if len(f.name.split("/")) != 2:
                        continue
                    tf.extract(f.name, path=cache_dir)
        except BaseException as e:
            raise TaskException(
                errno.EIO,
                "Unable to extract frozen update {0}: {1}".format(path, str(e))
            )

        config = Configuration.SystemConfiguration()
        # Exciting!  Now we need to have a SEQUENCE file, or it will fail verification.
        with open(os.path.join(cache_dir, "SEQUENCE"), "w") as s:
            s.write(config.SystemManifest().Sequence())
        # And now the SERVER file
        with open(os.path.join(cache_dir, "SERVER"), "w") as s:
            s.write(config.UpdateServerName())

        # Now we can go for the update apply task
        self.run_subtask_sync(
            'update.apply',
            reboot_post_install,
            progress_callback=lambda p, m='Installing updates from extracted tarfile', e=None: self.chunk_progress(0, 100, '', p, m, e)
        )


@accepts(bool)
@description("Applies cached updates")
class UpdateApplyTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Applying updates"

    def describe(self, reboot_post_install=False):
        return TaskDescription("Applying updates")

    def verify(self, reboot_post_install=False):
        return ['root']

    def update_progress(self, progress, message):
        self.set_progress(progress, message)

    def run(self, reboot_post_install=False):
        self.set_progress(0, 'Applying Updates...')
        handler = UpdateHandler(self.dispatcher, update_progress=self.update_progress)
        cache_dir = self.dispatcher.call_sync('update.update_cache_getter', 'cache_dir')
        if cache_dir is None:
            try:
                cache_dir = self.dispatcher.call_sync(
                    'system_dataset.request_directory', 'update'
                )
            except RpcException:
                cache_dir = '/var/tmp/update'
        new_manifest = Manifest.Manifest(require_signature=True)
        try:
            new_manifest.LoadPath(cache_dir + '/MANIFEST')
        except ManifestInvalidSignature as e:
            logger.error("Cached manifest has invalid signature: %s" % str(e))
            raise TaskException(errno.EINVAL, str(e))
        except FileNotFoundError as e:
            raise TaskException(
                errno.EIO,
                'No Manifest file found at path: {0}'.format(cache_dir + '/MANIFEST')
            )
        version = new_manifest.Version()
        # Note: for now we force reboots always, TODO: Fix in M3-M4
        try:
            result = ApplyUpdate(
                cache_dir,
                install_handler=handler.install_handler,
                progressFunc=handler.install_progress_handler,
                force_reboot=True
            )
        except ManifestInvalidSignature as e:
            logger.debug('UpdateApplyTask Error: Cached manifest has invalid signature: %s', e)
            raise TaskException(
                errno.EINVAL, 'Cached manifest has invalid signature: {0}'.format(str(e))
            )
        except UpdateBootEnvironmentException as e:
            logger.debug('UpdateApplyTask Boot Environment Error: {0}'.format(str(e)))
            raise TaskException(errno.EAGAIN, str(e))
        except UpdatePackageException as e:
            logger.debug('UpdateApplyTask Package Error: {0}'.format(str(e)))
            raise TaskException(errno.EAGAIN, str(e))
        except Exception as e:
            raise TaskException(
                errno.EAGAIN, 'Got exception {0} while trying to Apply Updates'.format(str(e))
            )
        if result is None:
            raise TaskException(errno.ENOENT, 'No downloaded Updates available to apply.')
        handler.finished = True
        handler.emit_update_details()
        self.dispatcher.call_sync('update.update_alert_set', 'UpdateInstalled', version)
        update_cache_value_dict = default_update_dict.copy()
        update_cache_value_dict.update({
            'installed': True,
            'installed_version': version
        })
        self.dispatcher.call_sync('update.update_cache_putter', update_cache_value_dict)
        message = 'Updates finished installing successfully'
        if reboot_post_install:
            message = 'Scheduling user specified reboot post succesfull update'
            # Note not using subtasks on purpose as they do not have queuing logic
            self.dispatcher.submit_task('system.reboot', 3)
        self.set_progress(100, message)


@description("Verify installation integrity")
@accepts()
class UpdateVerifyTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Verifying installation integrity"

    def describe(self):
        return TaskDescription("Verifying installation integrity")

    def verify(self):
        return [update_resource_string]

    def verify_handler(self, index, total, fname):
        self.set_progress(int(index * 100 / total), 'Verifying {0}'.format(fname))

    def run(self):
        try:
            error_flag, ed, warn_flag, wl = Configuration.do_verify(self.verify_handler)
        except Exception as e:
            raise TaskException(
                errno.EAGAIN, 'Got exception while verifying install: {0}'.format(str(e))
            )
        return {
            'checksum': ed['checksum'],
            'notfound': ed['notfound'],
            'wrongtype': ed['wrongtype'],
            'perm': wl,
            'error': error_flag,
            'warn': warn_flag,
        }


@description("Checks for updates from the update server and downloads them if available")
@accepts()
@returns(bool)
class CheckFetchUpdateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Checking for and downloading updates"

    def describe(self):
        return TaskDescription("Checking for and downloading updates")

    def verify(self):
        block = self.dispatcher.resource_graph.get_resource(update_resource_string)
        if block is not None and block.busy:
            raise VerifyException(errno.EBUSY, (
                'An update operation (Configuration/Downloading/Applying '
                'the updates) is already in the queue; please retry later'
            ))

        return []

    def run(self):
        result = False
        self.set_progress(0, 'Checking for new updates from update server')
        self.run_subtask_sync(
            'update.check',
            progress_callback=lambda p, m='Checking for updates from update server', e=None: self.chunk_progress(0, 10, '', p, m, e)
        )
        if self.dispatcher.call_sync('update.is_update_available'):
            self.set_progress(10, 'New updates found. Downloading them now')
            self.run_subtask_sync(
                'update.download',
                progress_callback=lambda p, m='New updates found. Downloading them now', e=None: self.chunk_progress(10, 100, '', p, m, e)
            )
            self.set_progress(100, 'Updates successfully Downloaded')
            result = True
        else:
            self.set_progress(100, 'No Updates Available')
        return result


@description("Checks for new updates, fetches if available, installs new/or downloaded updates")
@accepts(bool)
class UpdateNowTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Checking for updates and updating"

    def describe(self, reboot_post_install=False):
        return TaskDescription("Checking for updates and updating")

    def verify(self, reboot_post_install=False):
        return ['root']

    def run(self, reboot_post_install=False):
        self.set_progress(0, 'Checking for new updates')
        self.run_subtask_sync(
            'update.checkfetch',
            progress_callback=lambda p, m='Checking for new updates', e=None: self.chunk_progress(0, 50, '', p, m, e)
        )
        if self.dispatcher.call_sync('update.is_update_available'):
            self.set_progress(50, 'Installing downloaded updates now')
            self.run_subtask_sync(
                'update.apply',
                reboot_post_install,
                progress_callback=lambda p, m='Installing downloaded updates now', e=None: self.chunk_progress(50, 100, '', p, m, e)
            )
            self.set_progress(100, 'Updates Installed successfully')
            result = True
        else:
            self.add_warning(TaskWarning(errno.ENOENT, 'No Updates Available for Install'))
            self.set_progress(100, 'No Updates Available for Install')
            result = False

        return result


def _depends():
    return ['CalendarTasksPlugin', 'SystemDatasetPlugin', 'AlertPlugin']


def _init(dispatcher, plugin):
    # Register Schemas
    plugin.register_schema_definition('Update', {
        'type': 'object',
        'properties': {
            'train': {'type': 'string'},
            'check_auto': {'type': 'boolean'},
            'internal': {'type': 'boolean'},
            'update_server': {'type': 'string', 'readOnly': True},
        },
    })

    plugin.register_schema_definition('UpdateProgress', {
        'type': 'object',
        'properties': {
            'operation': {'$ref': 'UpdateProgressOperation'},
            'details': {'type': 'string'},
            'indeterminate': {'type': 'boolean'},
            'percent': {'type': 'integer'},
            'reboot': {'type': 'boolean'},
            'pkg_name': {'type': 'string'},
            'pkg_version': {'type': 'string'},
            'error': {'type': 'boolean'},
            'finished': {'type': 'boolean'}
        }
    })

    plugin.register_schema_definition('UpdateProgressOperation', {
        'type': 'string',
        'enum': ['DOWNLOADING', 'INSTALLING']
    })

    plugin.register_schema_definition('UpdateOps', {
        'type': 'object',
        'properties': {
            'operation': {'$ref': 'UpdateOpsOperation'},
            'new_name': {'type': ['string', 'null']},
            'new_version': {'type': ['string', 'null']},
            'previous_name': {'type': ['string', 'null']},
            'previous_version': {'type': ['string', 'null']},
        }
    })

    plugin.register_schema_definition('UpdateOpsOperation', {
        'type': 'string',
        'enum': ['delete', 'install', 'upgrade']
    })

    plugin.register_schema_definition('UpdateInfo', {
        'type': 'object',
        'properties': {
            'available': {'type': 'boolean'},
            'notes': {'type': 'object'},
            'notice': {'type': 'string'},
            'changelog': {
                'type': 'array',
                'items': {'type': 'string'},
            },
            'operations': {'$ref': 'UpdateOps'},
            'downloaded': {'type': 'boolean'},
            'version': {'type': 'string'},
            'installed': {'type': 'boolean'},
            'installed_version': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('UpdateTrain', {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'description': {'type': 'string'},
            'sequence': {'type': 'string'},
            'current': {'type': 'boolean'},
        }
    })

    # Register providers
    plugin.register_provider("update", UpdateProvider)

    # Register task handlers
    plugin.register_task_handler("update.update", UpdateConfigureTask)
    plugin.register_task_handler("update.check", CheckUpdateTask)
    plugin.register_task_handler("update.download", DownloadUpdateTask)
    plugin.register_task_handler("update.manual", UpdateManualTask)
    plugin.register_task_handler("update.apply", UpdateApplyTask)
    plugin.register_task_handler("update.verify", UpdateVerifyTask)
    plugin.register_task_handler("update.checkfetch", CheckFetchUpdateTask)
    plugin.register_task_handler("update.updatenow", UpdateNowTask)

    # Register Event Types
    plugin.register_event_type('update.in_progress', schema=h.ref('UpdateProgress'))
    plugin.register_event_type('update.update_info.updated')
    plugin.register_event_type('update.changed')

    # Register reources
    plugin.register_resource(Resource(update_resource_string), ['system', 'system-dataset'])

    # Get the Update Cache (if any) at system boot (and hence in init here)
    # Do this in parallel so that a failed cache generation does not take the
    # entire dispatcher start/restart with it (See Ticket: #12892)
    gevent.spawn(generate_update_cache, dispatcher)
