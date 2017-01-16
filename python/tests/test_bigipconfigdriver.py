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

import json
import os
import shutil
import sys
from string import Template
import time
import threading

import pytest

import bigipconfigdriver

_args_app_name = ['bigipconfigdriver.py']
_args_base = [
    '--username', 'booch',
    '--password', 'unbreakable',
    '--url', 'https://bigip.example.com'
    ]
_args_file = ['--config-file', '/tmp/file/../.././tmp/.//file']
_args_positional = ['partition_a', 'partition_b', 'partition_c']
_args_full = _args_base + _args_file + _args_positional


class MockBigIp():
    def __init__(self, expected_dict={'services': []}, fail=False,
                 notify_event=None, notify_after=0):
        self.calls = 0
        assert 'services' in expected_dict
        self._expected_dict = expected_dict
        self._fail = fail
        self._notify_event = notify_event
        self._notify_after = notify_after

    def regenerate_config_f5(self, services):
        assert type(services) is list
        assert services == self._expected_dict['services']
        self.calls = self.calls + 1

        if self._notify_event and self.calls == self._notify_after:
            self._notify_event.set()

        if not self._fail:
            return False
        else:
            self._fail = False
            return True


class MockEventHandler():
    def __init__(self):
        pass

    def on_change(self):
        pass


def test_handleargs_noargs(capsys):
    expected = ("usage: bigipconfigdriver.py [-h] --username USERNAME "
                "--password PASSWORD --url\n"
                "                            URL "
                "--config-file CONFIG_FILE\n"
                "                            [--verify-interval "
                "VERIFY_INTERVAL]\n"
                "                            [--log-level LOG_LEVEL]\n"
                "                            partition [partition ...]\n"
                "bigipconfigdriver.py: error: too few arguments\n")

    sys.argv[0:] = _args_app_name

    with pytest.raises(SystemExit):
        bigipconfigdriver._handle_args()

    out, err = capsys.readouterr()
    assert '' == out
    assert expected == err


def test_handleargs_notfilepath():
    sys.argv[0:] = _args_app_name
    sys.argv.extend(_args_base)
    sys.argv.extend(['--config-file', '/tmp/not-a-file/'])
    sys.argv.extend(_args_positional)

    with pytest.raises(bigipconfigdriver.ConfigError) as eio:
        bigipconfigdriver._handle_args()

    assert eio.value.message == 'must provide a file path'


def test_handleargs_expected():
    sys.argv[0:] = _args_app_name
    sys.argv.extend(_args_full)

    args = bigipconfigdriver._handle_args()

    assert args.config_file == '/tmp/file'
    assert args.username == 'booch'
    assert args.password == 'unbreakable'
    assert args.url == 'https://bigip.example.com'
    assert args.verify_interval == 30
    assert args.partitions == _args_positional


def test_handleargs_optional():
    sys.argv[0:] = _args_app_name
    sys.argv.extend(['--verify-interval', '1', '--log-level', 'INFO'])
    sys.argv.extend(_args_full)

    args = bigipconfigdriver._handle_args()

    assert args.config_file == '/tmp/file'
    assert args.username == 'booch'
    assert args.password == 'unbreakable'
    assert args.url == 'https://bigip.example.com'
    assert args.verify_interval == 1
    assert args.log_level == 'INFO'
    assert args.partitions == _args_positional


# IntervalTimer tests
def test_interval_init():
    def cb():
        pass

    with pytest.raises(bigipconfigdriver.IntervalTimerError):
        bigipconfigdriver.IntervalTimer(0, cb)

    with pytest.raises(bigipconfigdriver.IntervalTimerError):
        bigipconfigdriver.IntervalTimer(-1, cb)

    with pytest.raises(bigipconfigdriver.IntervalTimerError):
        bigipconfigdriver.IntervalTimer(-100, cb)

    with pytest.raises(ValueError):
        bigipconfigdriver.IntervalTimer("hello", cb)

    with pytest.raises(TypeError):
        bigipconfigdriver.IntervalTimer(0.1)

    with pytest.raises(bigipconfigdriver.IntervalTimerError):
        bigipconfigdriver.IntervalTimer(0.1, None)

    with pytest.raises(bigipconfigdriver.IntervalTimerError):
        bigipconfigdriver.IntervalTimer(0.1, "hello")


def test_interval():
    counter = {'times': 0}
    event = threading.Event()

    test_arg1 = "colonel atari"
    test_arg2 = "dexter"

    test_kwargs = {
        "baseball": "a sport",
        "football": "another sport"
    }

    def intervalCb(*args, **kwargs):
        assert args[0] == test_arg1
        assert args[1] == test_arg2

        assert 'baseball' in kwargs
        assert 'football' in kwargs
        assert 'interval' in kwargs

        assert kwargs['baseball'] == test_kwargs['baseball']
        assert kwargs['football'] == test_kwargs['football']

        counter['times'] = counter['times'] + 1
        if 5 == counter['times']:
            event.set()

    interval = None
    try:
        interval = bigipconfigdriver.IntervalTimer(0.25, intervalCb,
                                                   (test_arg1, test_arg2),
                                                   test_kwargs)
        assert interval is not None
        assert interval._stop.is_set() is True
        assert interval._restart.is_set() is False
        assert interval._destroy.is_set() is False
        assert interval.is_running() is False

        test_kwargs['interval'] = interval

        interval.start()
        assert interval._stop.is_set() is False
        assert interval._restart.is_set() is True
        assert interval._destroy.is_set() is False
        assert interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True

        interval.stop()
        assert interval._stop.is_set() is True
        assert interval._restart.is_set() is False
        assert interval._destroy.is_set() is False
        assert interval.is_running() is False

        event.clear()
        counter['times'] = 0

        interval.start()
        assert interval._stop.is_set() is False
        assert interval._restart.is_set() is True
        assert interval._destroy.is_set() is False
        assert interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True

        interval.stop()
        assert interval._stop.is_set() is True
        assert interval._restart.is_set() is False
        assert interval._destroy.is_set() is False
        assert interval.is_running() is False

        event.clear()
        counter['times'] = 0

        interval.start()
        assert interval._stop.is_set() is False
        assert interval._restart.is_set() is True
        assert interval._destroy.is_set() is False
        assert interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True

        event.clear()
        counter['times'] = 0

        interval.start()
        assert interval._stop.is_set() is False
        assert interval._restart.is_set() is True
        assert interval._destroy.is_set() is False
        assert interval.is_running() is True

        interval.destroy()
        interval.join(30)
        assert interval.is_alive() is False
    finally:
        assert interval is not None


def test_interval_startdestroy():
    def cb():
        pass

    interval = None
    try:
        interval = bigipconfigdriver.IntervalTimer(0.25, cb)
        assert interval is not None
        assert interval._stop.is_set() is True
        assert interval._restart.is_set() is False
        assert interval._destroy.is_set() is False
        assert interval.is_running() is False

        interval.start()
        assert interval._stop.is_set() is False
        assert interval._restart.is_set() is True
        assert interval._destroy.is_set() is False
        assert interval.is_running() is True

        interval.destroy()
        interval.join(30)
        assert interval.is_alive() is False
    finally:
        assert interval is not None


def test_interval_nostartdestroy():
    def cb():
        pass

    interval = None
    try:
        interval = bigipconfigdriver.IntervalTimer(0.25, cb)
        assert interval is not None
        assert interval._stop.is_set() is True
        assert interval._restart.is_set() is False
        assert interval._destroy.is_set() is False
        assert interval.is_running() is False

        assert interval.is_alive() is False

        interval.destroy()
        assert interval._destroy.is_set() is True
        assert interval._restart.is_set() is True
        assert interval._stop.is_set() is True
        assert interval.is_alive() is False

        interval.join(30)
    except RuntimeError:
        assert interval.is_alive() is False
    finally:
        assert interval is not None


# ConfigWatcher tests
def test_configwatcher_init(request):
    expected_dir_template = Template('/tmp/$pid')
    expected_dir = expected_dir_template.substitute(pid=os.getpid())
    expected_file = expected_dir + '/file'

    def fin():
        shutil.rmtree(expected_dir, ignore_errors=True)

    request.addfinalizer(fin)

    watcher = bigipconfigdriver.ConfigWatcher(expected_file, MockBigIp(),
                                              MockEventHandler().on_change)

    assert watcher._config_file == expected_file
    assert watcher._config_dir == expected_dir
    assert watcher._config_stats is None
    assert watcher._polling is False
    assert watcher._running is False

    # Test with file on created
    expected_digest = '\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04' + \
        '\xe9\x80\t\x98\xec\xf8B~'

    os.mkdir(expected_dir)
    with open(expected_file, 'w+'):
        os.utime(expected_file, None)

    watcherExist = bigipconfigdriver.ConfigWatcher(
            expected_file, MockBigIp(),
            MockEventHandler().on_change)

    assert watcherExist._config_file == expected_file
    assert watcherExist._config_dir == expected_dir
    assert watcherExist._config_stats == expected_digest
    assert watcher._polling is False
    assert watcher._running is False


def test_configwatcher_shouldwatch():
    watch_file_template = Template('/tmp/$pid')
    watch_file = watch_file_template.substitute(pid=os.getpid())

    watcher = bigipconfigdriver.ConfigWatcher(watch_file, MockBigIp(),
                                              MockEventHandler().on_change)

    assert watcher._should_watch(watch_file) is True

    assert watcher._should_watch('/tmp/not-config-file') is False


def test_configwatcher_loop(request):
    watch_dir_template = Template('/tmp/$pid')
    watch_dir = watch_dir_template.substitute(pid=os.getpid())
    watch_file = watch_dir + '/file'

    def fin():
        shutil.rmtree(watch_dir, ignore_errors=True)

    request.addfinalizer(fin)

    expected_changes = [True, True, False, True, True, True]
    expected_digests = [
        '\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~',
        '\xd7-\x16\xde\x92\xf2\xb6\xc1\x05\xce\xabj\x84\xcf\xcaz',
        '\xd7-\x16\xde\x92\xf2\xb6\xc1\x05\xce\xabj\x84\xcf\xcaz', None,
        '\xd7-\x16\xde\x92\xf2\xb6\xc1\x05\xce\xabj\x84\xcf\xcaz', None
    ]

    watcher = bigipconfigdriver.ConfigWatcher(watch_file, MockBigIp(),
                                              MockEventHandler().on_change)

    # loop will block and threading will introduce synchronization complexities
    # assuming pyinotify signals properly and only testing the _is_changed
    # function
    assert watcher._config_stats is None

    # IN_CREATE event
    os.mkdir(watch_dir)
    with open(watch_file, 'w+') as file_handle:
        (changed, md5sum) = watcher._is_changed()
        assert changed == expected_changes[0]
        assert md5sum == expected_digests[0]
        watcher._config_stats = md5sum

        file_handle.write('Senatus Populusque Romanus')

    # IN_CLOSE_WRITE event
    (changed, md5sum) = watcher._is_changed()
    assert changed == expected_changes[1]
    assert md5sum == expected_digests[1]
    watcher._config_stats = md5sum

    # IN_CLOSE_WRITE no change
    with open(watch_file, 'w') as file_handle:
        file_handle.write('Senatus Populusque Romanus')
    (changed, md5sum) = watcher._is_changed()
    assert changed == expected_changes[2]
    assert md5sum == expected_digests[2]

    # IN_MOVED_FROM event
    shutil.move(watch_file, watch_dir + '/file2')
    (changed, md5sum) = watcher._is_changed()
    assert changed == expected_changes[3]
    assert md5sum == expected_digests[3]
    watcher._config_stats = md5sum

    # IN_MOVED_TO event
    shutil.move(watch_dir + '/file2', watch_file)
    (changed, md5sum) = watcher._is_changed()
    assert changed == expected_changes[4]
    assert md5sum == expected_digests[4]
    watcher._config_stats = md5sum

    # IN_DELETE event
    os.unlink(watch_file)
    (changed, md5sum) = watcher._is_changed()
    assert changed == expected_changes[5]
    assert md5sum == expected_digests[5]


def test_confighandler_lifecycle():
    handler = None
    try:
        bigip = MockBigIp()
        handler = bigipconfigdriver.ConfigHandler('/tmp/config', bigip, 0)

        assert handler._thread in threading.enumerate()
        assert handler._thread.is_alive() is True
        assert handler._pending_reset is False
        assert handler._stop is False
        assert handler._bigip == bigip
        assert handler._config_file == '/tmp/config'
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread not in threading.enumerate()
        assert handler._thread.is_alive() is False
        assert handler._stop is True


def test_confighandler_parse_config(request):
    handler = None
    try:
        bigip = MockBigIp()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, bigip, 0)

        r = handler._parse_config()
        assert r is None

        obj = {}
        obj['field1'] = 'one'
        obj['field_string'] = 'string'
        obj['field_number'] = 10

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = handler._parse_config()
        assert r is not None
        assert r['field1'] == obj['field1']
        assert r['field_string'] == obj['field_string']
        assert r['field_number'] == obj['field_number']
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_confighandler_reset(request):
    handler = None
    try:
        obj = {}
        obj['services'] = []
        obj['services'].append({'field': 8080})
        obj['services'].append({'field': 9090})
        obj['services'].append({'field': 10101})

        bigip = MockBigIp(obj)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, bigip, 0)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert bigip.calls == 0

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        assert handler._thread.is_alive() is True

        handler.notify_reset()
        time.sleep(0.1)
        assert bigip.calls == 1

        handler.notify_reset()
        time.sleep(0.1)
        assert bigip.calls == 2

        handler.notify_reset()
        time.sleep(0.1)
        assert bigip.calls == 3

        # in the failure case we'll respond with a notify_reset to try again
        # therefore, we'll tick twice in for this test case
        bigip._fail = True
        handler.notify_reset()
        time.sleep(0.1)
        assert bigip.calls == 5
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_confighandler_checkpoint(request):
    handler = None
    try:
        obj = {}
        obj['services'] = []
        obj['services'].append({'field': 8080})
        obj['services'].append({'field': 9090})
        obj['services'].append({'field': 10101})

        event = threading.Event()
        bigip = MockBigIp(obj, notify_event=event, notify_after=5)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, bigip,
                                                  0.25)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert bigip.calls == 0

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        assert handler._thread.is_alive() is True

        assert handler._interval.is_running() is False
        handler.notify_reset()
        time.sleep(0.1)
        assert handler._interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False
        assert handler._interval.is_running() is False


def test_confighandler_checkpointstopafterfailure(request):
    handler = None
    try:
        obj = {}
        obj['services'] = []
        obj['services'].append({'field': 8080})
        obj['services'].append({'field': 9090})
        obj['services'].append({'field': 10101})

        event = threading.Event()
        bigip = MockBigIp(obj, fail=True, notify_event=event, notify_after=5)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, bigip,
                                                  0.25)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert bigip.calls == 0

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        assert handler._thread.is_alive() is True

        assert handler._interval.is_running() is False

        # get rid of the real notify reset so we only do_reset once in
        # this test
        def p():
            pass
        handler.notify_reset = p
        handler._condition.acquire()
        handler._pending_reset = True
        handler._condition.notify()
        handler._condition.release()
        time.sleep(0.1)

        # should be false here because an invalid config stops the interval
        assert handler._interval.is_running() is False
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False
        assert handler._interval.is_running() is False
