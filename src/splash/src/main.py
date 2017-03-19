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

import sys
import curses
from bsd import sysctl
from threading import Condition
from freenas.serviced import subscribe
from freenas.utils import query as q


CRITICAL_JOBS = [
    'org.freebsd.devd',
    'org.freenas.datastore',
    'org.freenas.dispatcher',
    'org.freenas.etcd',
    'org.freenas.logd'
]


class VerboseFrontend(object):
    def __init__(self, context):
        self.context = context
        self.last_msg = None

    def init(self):
        print('Booting {0}...'.format(self.context.version))

    def draw(self, msg, extra=None):
        if extra is None:
            extra = {}
        if msg != self.last_msg:
            print(msg)
            self.last_msg = msg

    def cleanup(self):
        pass


class CursesFrontend(object):
    def __init__(self, context):
        self.context = context
        self.stdscr = None
        self.mainwin = None
        self.statuswin = None
        self.maxx = None
        self.maxy = None

    def init(self):
        self.stdscr = curses.initscr()
        self.maxy, self.maxx = self.stdscr.getmaxyx()
        self.mainwin = curses.newwin(1, self.maxx, 1, 2)
        self.statuswin = curses.newwin(1, self.maxx, self.maxy - 1, 0)
        self.migrationwin = curses.newwin(2, self.maxx, self.maxy - 5, 0)
        # self.migrationwin.bkgd(ord(' '), curses.A_STANDOUT)
        self.statuswin.bkgd(ord(' '), curses.A_REVERSE)

    def cleanup(self):
        curses.endwin()

    def draw(self, msg, extra=None):
        if extra is None:
            extra = {}
        # Seatbelt to prevent ncurses error when message is longer than 80 chars
        msg = msg[:75] + '...' if len(msg) > 79 else msg
        self.stdscr.clear()
        self.stdscr.redrawwin()
        self.mainwin.addstr(0, 0, 'Booting {0}...'.format(self.context.version), curses.A_BOLD)
        self.statuswin.clear()
        try:
            self.statuswin.addstr(0, 2, msg)
        except curses.error:
            pass
        else:
            self.statuswin.refresh()
        if extra.get('plugin') == 'MigrationPlugin' and extra.get('status') != 'NOT_NEEDED':
            apps_migrated = ', '.join(extra.get('apps_migrated', []))
            apps_migrated = 'Apps done: ' + apps_migrated if apps_migrated else 'Initializing...'
            self.migrationwin.clear()
            try:
                migration_prog = extra.get('migration_progress', 0)
                done_perct = '#' * int(migration_prog / 5)
                left_perct = (20 - len(done_perct)) * '_'
                self.migrationwin.addstr(
                    0, 2, f"FreeNAS 9 migration progress: [{done_perct}{left_perct}] {migration_prog}%"
                )
                self.migrationwin.addstr(
                    1, 2, apps_migrated[:75] + '...' if len(apps_migrated) > 79 else apps_migrated
                )
            except (ValueError, curses.error):
                pass
            else:
                self.migrationwin.refresh()
        self.mainwin.refresh()


class SDLFrontend(object):
    def __init__(self, context):
        self.context = context


class Main(object):
    def __init__(self):
        self.cv = Condition()
        self.etc = False
        self.network = False
        self.exiting = False
        self.migration_done = False
        self.migration_status = {}
        self.failed_job = None
        self.msg = 'Loading...'
        with open('/etc/version', 'r') as f:
            self.version = f.read().strip()

    def event(self, name, args):
        with self.cv:
            if name == 'serviced.job.started':
                if args['Label'] == 'org.freenas.etcd':
                    self.etc = True

                if args['Label'] == 'org.freenas.networkd':
                    self.network = True

                if args['Anonymous']:
                    return

                self.msg = 'Loaded {0}'.format(args['Label'])
                self.cv.notify_all()

            if name == 'serviced.job.status':
                if q.get(args, 'Extra.plugin') == 'MigrationPlugin':
                    self.migration_status = q.get(args, 'Extra', {})
                    self.msg = args.get('Message', 'Migrating FreeNAS 9.x settings...')
                else:
                    self.msg = '{0}: {1}'.format(args['Label'], args['Message'])
                self.cv.notify_all()

            if name == 'serviced.job.error' and args['Label'] in CRITICAL_JOBS:
                self.exiting = True
                self.failed_job = args['Label']
                self.cv.notify_all()

    def select_frontend(self):
        if sysctl.sysctlbyname('debug.bootverbose') == 1:
            return VerboseFrontend(self)

        return CursesFrontend(self)

    def main(self):
        subscribe(self.event)
        frontend = self.select_frontend()
        migration_states = ['NOT_NEEDED', 'FINISHED', 'FAILED', 'STOPPED']
        try:
            frontend.init()
            frontend.draw(self.msg, self.migration_status)
            with self.cv:
                while True:
                    self.cv.wait(0.5)
                    if (
                        self.etc and
                        self.network and
                        self.migration_status.get('status') in migration_states
                    ):
                        break

                    if self.exiting:
                        break

                    frontend.draw(self.msg, self.migration_status)
        finally:
            frontend.cleanup()

        if self.failed_job:
            print('Critical system job {0} failed to start.'.format(self.failed_job))
            print('Dropping into single user mode')
            sys.exit(1)


if __name__ == '__main__':
    m = Main()
    m.main()
