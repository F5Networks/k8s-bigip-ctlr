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
import json
import logging
import os
import os.path
import sys
import time
import threading

import pyinotify

from _f5 import CloudBigIP

log = logging.getLogger(__name__)
console = logging.StreamHandler()
console.setFormatter(
    logging.Formatter("[%(asctime)s %(name)s %(levelname)s] %(message)s"))
root_logger = logging.getLogger()
root_logger.addHandler(console)
root_logger.setLevel(logging.INFO)


class IntervalTimerError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


class IntervalTimer(threading.Thread):

    def __init__(self, interval, cb, args=[], kwargs={}):
        float(interval)
        if 0 >= interval:
            raise IntervalTimerError("interval must be greater than 0")

        if not cb or not callable(cb):
            raise IntervalTimerError("cb must be callable object")

        threading.Thread.__init__(self)
        self._interval = interval
        self._cb = cb
        self._args = args
        self._kwargs = kwargs
        self._restart = threading.Event()
        self._stop = threading.Event()
        self._stop.set()
        self._destroy = threading.Event()

    def start(self):
        self._start()

        if self.is_alive() is False:
            super(IntervalTimer, self).start()

    def _start(self):
        self._stop.clear()
        self._restart.set()

    def stop(self):
        self._restart.clear()
        self._stop.set()

    def destroy(self):
        self._destroy.set()
        if not self._restart.is_set():
            self._restart.set()
        if not self._stop.is_set():
            self._stop.set()

    def is_running(self):
        return not self._stop.is_set() and self._restart.is_set()

    def run(self):
        while True:
            if not self._stop.wait(self._interval):
                if not self._destroy.is_set():
                    self._cb(*self._args, **self._kwargs)
            else:
                self._restart.wait()

            if self._destroy.is_set():
                break


class ConfigError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


class BigipWatcherError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


class ConfigHandler():
    def __init__(self, config_file, bigip, verify_interval):
        self._config_file = config_file
        self._bigip = bigip
        self._verify_interval = verify_interval

        self._condition = threading.Condition()
        self._thread = threading.Thread(target=self._do_reset)
        self._pending_reset = False
        self._stop = False

        if self._verify_interval > 0:
            self._interval = IntervalTimer(self._verify_interval,
                                           self.notify_reset)
        else:
            self._interval = None
        self._thread.start()

    def stop(self):
        self._condition.acquire()
        self._stop = True
        self._condition.notify()
        self._condition.release()

    def _parse_config(self):
        if os.path.exists(self._config_file):
            with open(self._config_file) as config:
                config_json = json.load(config)
                log.debug('loaded configuration file successfully')
                return config_json
        else:
            return None

    def notify_reset(self):
        self._condition.acquire()
        self._pending_reset = True
        self._condition.notify()
        self._condition.release()

    def _do_reset(self):
        log.debug('config handler thread start')

        with self._condition:
            while True:
                self._condition.acquire()
                if not self._pending_reset:
                    self._condition.wait()
                log.debug('config handler woken for reset')

                if self._stop:
                    log.info('stopping config handler')
                    break

                self._pending_reset = False
                self._condition.release()

                try:
                    start_time = time.time()

                    config = self._parse_config()

                    # FIXME(yacobucci) update regenerate_config_f5 to take
                    # the full config blob
                    services = None
                    try:
                        services = config['services']
                    except (TypeError, KeyError):
                        services = []

                    if self._bigip.regenerate_config_f5(services):
                        # Timeout occurred, do a reset so that we try again
                        log.warning(
                            'regenerate operation timed out, resetting')

                        if (self._interval and self._interval.is_running() is
                                True):
                            self._interval.stop()
                        self.notify_reset()
                    else:
                        if (self._interval and self._interval.is_running() is
                                False):
                            self._interval.start()

                    log.debug('updating tasks finished, took %s seconds',
                              time.time() - start_time)
                except IOError as e:
                    log.warning(e)
                except ValueError as e:
                    log.warning(e)
                except:
                    log.exception('Unexpected error')

        if self._interval:
            self._interval.destroy()


class ConfigWatcher(pyinotify.ProcessEvent):
    def __init__(self, config_file, bigip, on_change):
        basename = os.path.basename(config_file)
        if not basename or 0 == len(basename):
            raise BigipWatcherError('config_file must be a file path')

        self._config_file = config_file
        self._bigip = bigip
        self._on_change = on_change

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
                log.debug('config file {} changed, parent gone'.format(
                    self._config_file))
                self._config_stats = None
                self._on_change()

        if self._should_watch(event.pathname):
            (changed, md5) = self._is_changed()

            if changed:
                log.debug('config file {0} changed - signalling bigip'.format(
                    self._config_file, self._config_stats, md5))
                self._config_stats = md5
                self._on_change()


def _handle_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-v',
        '--verbose',
        default=False,
        action="store_true",
        help='Output verbose debug message')
    parser.add_argument(
            '--username',
            type=str,
            required=True,
            help='BigIp username')
    parser.add_argument(
            '--password',
            type=str,
            required=True,
            help='BigIp password')
    parser.add_argument(
            '--hostname',
            type=str,
            required=True,
            help='Hostname / IP address of BigIp')
    parser.add_argument(
            '--config-file',
            type=str,
            required=True,
            help='BigIp configuration file')
    parser.add_argument(
            '--verify-interval',
            type=int,
            default=30,
            help='Interval to checkpoint BigIp configuration')
    parser.add_argument(
            'partitions', metavar='partition', type=str, nargs='+',
            help='List of BigIp partitions available to the controller')
    args = parser.parse_args()

    basename = os.path.basename(args.config_file)
    if not basename or 0 == len(basename):
        raise ConfigError('must provide a file path')

    args.config_file = os.path.realpath(args.config_file)

    return args


def main():
    try:
        args = _handle_args()

        if args.verbose:
            root_logger.setLevel(logging.DEBUG)

        bigip = CloudBigIP('kubernetes', args.hostname, args.username,
                           args.password, args.partitions)

        handler = ConfigHandler(args.config_file, bigip, args.verify_interval)
        if os.path.exists(args.config_file):
            handler.notify_reset()

        watcher = ConfigWatcher(args.config_file, bigip, handler.notify_reset)
        watcher.loop()
        handler.stop()
    except BigipWatcherError, err:
        log.error(err)
        sys.exit(1)

    return 0


if __name__ == "__main__":
    main()
