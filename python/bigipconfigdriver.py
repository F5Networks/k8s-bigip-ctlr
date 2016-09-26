#!/usr/bin/env python

# Copyright 2016 F5 Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import hashlib
import logging
import os
import os.path
import sys
import time

import pyinotify

# FIXME(yacobucci) add bigip module when available
# import bigip configurator module

log = logging.getLogger('bigipconfigdriver')
console = logging.StreamHandler()
console.setFormatter(
    logging.Formatter("[%(asctime)s %(name)s %(levelname)s] %(message)s"))
log.addHandler(console)
log.setLevel(logging.INFO)


class ConfigError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


class BigipWatcherError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


class ConfigWatcher(pyinotify.ProcessEvent):
    def __init__(self, config_file):
        basename = os.path.basename(config_file)
        if not basename or 0 == len(basename):
            raise BigipWatcherError('config_file must be a file path')

        self._config_file = config_file
        self._config_dir = os.path.dirname(self._config_file)
        self._config_stats = None
        if os.path.exists(self._config_file):
            self._config_stats = self._md5()

        self._running = False
        self._polling = False

    def _loop_check(self, notifier):
        if self._polling:
            log.debug('inotify loop ended - returning to polling mode')
            return True
        else:
            return False

    def loop(self):
        self._running = True
        if not os.path.exists(self._config_dir):
            log.info(
                'configured directory doesn\'t exist {}, entering poll loop'.
                format(self._config_dir))
            self._polling = True

        while self._running:
            try:
                while self._polling:
                    if self._polling:
                        if os.path.exists(self._config_dir):
                            log.debug('found watchable directory - {}'.format(
                                self._config_dir))
                            self._polling = False
                            break
                        else:
                            log.debug('waiting for watchable directory - {}'.
                                      format(self._config_dir))
                            time.sleep(1)

                try:
                    _wm = pyinotify.WatchManager()
                    _notifier = pyinotify.Notifier(_wm, default_proc_fun=self)
                    _notifier.coalesce_events(True)
                    mask = (pyinotify.IN_CREATE | pyinotify.IN_DELETE |
                            pyinotify.IN_MOVED_FROM | pyinotify.IN_MOVED_TO |
                            pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVE_SELF |
                            pyinotify.IN_DELETE_SELF)
                    _wm.add_watch(
                        path=self._config_dir,
                        mask=mask,
                        quiet=False,
                        exclude_filter=lambda path: False)

                    log.info('entering inotify loop to watch {}'.format(
                        self._config_file))
                    _notifier.loop(callback=self._loop_check)

                    if (not self._polling and _notifier._fd is None):
                        log.info('terminating')
                        self._running = False

                except pyinotify.WatchManagerError, err:
                    raise BigipWatcherError(str(err))
                except pyinotify.NotifierError, err:
                    raise BigipWatcherError(str(err))
            except KeyboardInterrupt:
                log.info('terminating')
                self._running = False

    def _md5(self):
        md5 = hashlib.md5()

        with open(self._config_file, 'rb') as f:
            while True:
                buf = f.read(4096)
                if not buf:
                    break
                md5.update(buf)
        return md5.digest()

    def _should_watch(self, pathname):
        if pathname == self._config_file:
            return True
        return False

    def _is_changed(self):
        changed = False
        cur_hash = None
        if not os.path.exists(self._config_file):
            if cur_hash != self._config_stats:
                changed = True
            else:
                changed = False
        else:
            cur_hash = self._md5()
            if cur_hash != self._config_stats:
                changed = True
            else:
                changed = False

        return (changed, cur_hash)

    def process_default(self, event):
        if (pyinotify.IN_DELETE_SELF == event.mask or
                pyinotify.IN_MOVE_SELF == event.mask):
            log.warn(
                'watchpoint {} has been moved or destroyed, using poll loop'.
                format(self._config_dir))
            self._polling = True

            if self._config_stats is not None:
                # FIXME(yacobucci) changed
                log.debug('config file {} changed, parent gone'.format(
                    self._config_file))
                self._config_stats = None

        if self._should_watch(event.pathname):
            (changed, md5) = self._is_changed()

            if changed:
                # FIXME(yacobucci) if we've changed notify the BigIp module
                log.debug('config file {0} changed - signalling bigip'.format(
                    self._config_file, self._config_stats, md5))
                self._config_stats = md5


def _handle_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-v',
        '--verbose',
        default=False,
        action="store_true",
        help='Output verbose debug message')
    parser.add_argument(
        'config_file',
        metavar='config-file',
        type=str,
        help='BigIp configuration file')
    args = parser.parse_args()

    # FIXME(yacobucci) additional arguments required for connecting to
    # BigIp

    basename = os.path.basename(args.config_file)
    if not basename or 0 == len(basename):
        raise ConfigError('must provide a file path')

    realpath = os.path.realpath(args.config_file)

    return (realpath, args.verbose)


def main():
    try:
        (realpath, verbose) = _handle_args()

        if verbose:
            log.setLevel(logging.DEBUG)

        # FIXME(yacobucci) initialize the world if config file exists

        watcher = ConfigWatcher(realpath)
        watcher.loop()
    except BigipWatcherError, err:
        log.error(err)
        sys.exit(1)

    return 0


if __name__ == "__main__":
    main()
