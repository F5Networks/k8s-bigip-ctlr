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
from __future__ import absolute_import

from copy import deepcopy
import json
import logging
import os
import shutil
from string import Template
import sys
import threading
import time

from f5_cccl.exceptions import F5CcclValidationError

import pytest

from .. import bigipconfigdriver

_args_app_name = ['bigipconfigdriver.py']

_cloud_config = {
    'bigip': {
        'username': 'test',
        'url': 'https://127.0.0.1',
        'password': 'admin',
        'partition': 'test'
    },
    'resources': {
        "test": {
            'virtualServer': {
                'frontend': {
                    'virtualServerName': 'test.service',
                    'partition': 'test',
                    'virtualAddress': {
                        'bindAddr': '127.0.0.1',
                        'port': 8080
                    },
                    'mode': 'http',
                    'balance': 'round-robin'
                },
                'backend': {
                    'poolMemberAddrs': [
                        '192.168.0.1',
                        '192.168.0.2'
                    ],
                    'serviceName': 'myService',
                    'servicePort': 80
                }
            }
        }
    },
    'global': {
        'verify-interval': 0.25,
        'log-level': u'INFO'
    }
}

_expected_bigip_config = {
    'network': {},
    'ltm': {
        'test.service': {
            'virtual_address': '127.0.0.1',
            'name': 'test.service',
            'partition': 'test',
            'virtual': {
                'disabled': False,
                'profiles': [
                    {
                        'partition': 'Common',
                        'name': 'http'
                    }
                ],
                'pool': '/test/test.service',
                'ipProtocol': 'tcp',
                'destination': '/test/127.0.0.1:8080',
                'enabled': True,
                'sourceAddressTranslation': {
                    'type': 'automap'
                }
            },
            'health': [],
            'nodes': {
                '192.168.0.2': {
                    'state': 'user-up',
                    'session': 'user-enabled'
                },
                '192.168.0.1': {
                    'state': 'user-up',
                    'session': 'user-enabled'
                }
            },
            'pool': {
                'monitor': None,
                'loadBalancingMode': u'round-robin'
            }
        }
    }
}


class MockMgr(bigipconfigdriver.CloudServiceManager):
    def __init__(self, fail=False, notify_event=None, notify_after=0,
                 handle_results=None):
        self._partition = _cloud_config['bigip']['partition']
        self.calls = 0
        self._fail = fail
        self._notify_event = notify_event
        self._notify_after = notify_after
        self._handle_results = handle_results
        self._schema = None

    def get_partition(self):
        return self._partition

    def _apply_ltm_config(self, cfg):
        return self._apply_config(cfg)

    def _apply_net_config(self, cfg):
        return self._apply_config(cfg)

    def _apply_config(self, cfg):
        expected_bigip_config = json.loads(json.dumps(cfg))
        actual_bigip_config = json.loads(json.dumps(cfg))
        assert expected_bigip_config == actual_bigip_config

        self.calls = self.calls + 1

        if self._notify_event and self.calls == self._notify_after:
            self._notify_event.set()

        if self._handle_results:
            self._handle_results()
        else:
            if self._fail:
                self._fail = False
                raise F5CcclValidationError

        return 0


class MockEventHandler():
    def __init__(self):
        pass

    def on_change(self):
        pass


def test_handleargs_noargs(capsys):
    expected = "usage: bigipconfigdriver.py [-h] --config-file CONFIG_FILE\n"\
               "bigipconfigdriver.py: error:"\
               " argument --config-file is required\n"

    sys.argv[0:] = _args_app_name

    with pytest.raises(SystemExit):
        bigipconfigdriver._handle_args()

    out, err = capsys.readouterr()
    assert '' == out
    assert expected == err


def test_handleargs_notfilepath():
    sys.argv[0:] = _args_app_name
    sys.argv.extend(['--config-file', '/tmp/not-a-file/'])

    with pytest.raises(bigipconfigdriver.ConfigError) as eio:
        bigipconfigdriver._handle_args()

    assert eio.value.message == 'must provide a file path'


def test_handleargs_unexpected(capsys):
    expected = "usage: bigipconfigdriver.py [-h] --config-file CONFIG_FILE\n"\
               "bigipconfigdriver.py: error:"\
               " unrecognized arguments: --bad-arg\n"

    sys.argv[0:] = _args_app_name
    sys.argv.extend(['--config-file', '/tmp/file'])
    sys.argv.extend(['--bad-arg'])

    with pytest.raises(SystemExit):
        bigipconfigdriver._handle_args()

    out, err = capsys.readouterr()
    assert '' == out
    assert expected == err


def test_handleargs_expected():
    sys.argv[0:] = _args_app_name
    sys.argv.extend(['--config-file', '/tmp/.././tmp/file'])

    args = bigipconfigdriver._handle_args()

    assert args.config_file == '/tmp/file'


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


def test_interval_repeat():
    counter = {'times': 0}
    event = threading.Event()

    def intervalCb():
        counter['times'] = counter['times'] + 1
        if 5 == counter['times']:
            event.set()

    interval = None
    try:
        interval = bigipconfigdriver.IntervalTimer(0.25, intervalCb)
        assert interval is not None
        assert interval.is_running() is False

        interval.start()
        assert interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True

        interval.stop()
        assert interval.is_running() is False

        event.clear()
        counter['times'] = 0

        interval.start()
        assert interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True

        interval.stop()
        assert interval.is_running() is False

        event.clear()
        counter['times'] = 0

        interval.start()
        assert interval.is_running() is True

        event.wait(30)
        assert event.is_set() is True

        event.clear()
        counter['times'] = 0

        interval.start()
        assert interval.is_running() is True

        interval.stop()
        assert interval.is_running() is False
    finally:
        assert interval is not None


def test_interval_startstop():
    def cb():
        pass

    interval = None
    try:
        interval = bigipconfigdriver.IntervalTimer(0.25, cb)
        assert interval is not None
        assert interval.is_running() is False

        interval.start()
        assert interval.is_running() is True

        interval.stop()
        assert interval.is_running() is False
    finally:
        assert interval is not None


def test_interval_nostartstop():
    def cb():
        pass

    interval = None
    try:
        interval = bigipconfigdriver.IntervalTimer(0.25, cb)
        assert interval is not None
        assert interval.is_running() is False

        interval.stop()
        assert interval.is_running() is False

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

    watcher = bigipconfigdriver.ConfigWatcher(expected_file,
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
            expected_file,
            MockEventHandler().on_change)

    assert watcherExist._config_file == expected_file
    assert watcherExist._config_dir == expected_dir
    assert watcherExist._config_stats == expected_digest
    assert watcher._polling is False
    assert watcher._running is False


def test_configwatcher_shouldwatch():
    watch_file_template = Template('/tmp/$pid')
    watch_file = watch_file_template.substitute(pid=os.getpid())

    watcher = bigipconfigdriver.ConfigWatcher(watch_file,
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

    watcher = bigipconfigdriver.ConfigWatcher(watch_file,
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
        mgr = MockMgr()
        handler = bigipconfigdriver.ConfigHandler('/tmp/config', [mgr], 30)

        assert handler._thread in threading.enumerate()
        assert handler._thread.is_alive() is True
        assert handler._pending_reset is False
        assert handler._stop is False
        assert handler._managers == [mgr]
        assert handler._config_file == '/tmp/config'
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread not in threading.enumerate()
        assert handler._thread.is_alive() is False
        assert handler._stop is True


def test_parse_config(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, [mgr], 30)

        r = bigipconfigdriver._parse_config(config_file)
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

        r = bigipconfigdriver._parse_config(config_file)
        assert r is not None
        assert r['field1'] == obj['field1']
        assert r['field_string'] == obj['field_string']
        assert r['field_number'] == obj['field_number']
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['global'] = {'log-level': 'WARNING',
                         'verify-interval': 10,
                         'vxlan-partition': 'test'}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, vx_p = \
            bigipconfigdriver._handle_global_config(r)
        assert verify_interval == 10
        assert level == logging.WARNING
        assert vx_p == 'test'

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config_defaults(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['global'] = {}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, vx_p = \
            bigipconfigdriver._handle_global_config(r)
        assert verify_interval == bigipconfigdriver.DEFAULT_VERIFY_INTERVAL
        assert level == bigipconfigdriver.DEFAULT_LOG_LEVEL
        assert vx_p is None

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config_bad_string_log_level(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {"global": {"log-level": "everything", "verify-interval": 100}}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, _ = bigipconfigdriver._handle_global_config(r)
        assert verify_interval == 100
        assert level == bigipconfigdriver.DEFAULT_LOG_LEVEL

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config_number_log_level(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {"global": {"log-level": 55, "verify-interval": 100}}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, _ = bigipconfigdriver._handle_global_config(r)
        assert verify_interval == 100
        assert level == bigipconfigdriver.DEFAULT_LOG_LEVEL

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config_negative_verify_interval(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {"global": {"log-level": "ERROR", "verify-interval": -1}}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, _ = bigipconfigdriver._handle_global_config(r)
        assert verify_interval == bigipconfigdriver.DEFAULT_VERIFY_INTERVAL
        assert level == logging.ERROR

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_global_config_string_verify_interval(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {"global": {"log-level": "ERROR", "verify-interval": "hundred"}}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        verify_interval, level, _ = bigipconfigdriver._handle_global_config(r)
        assert verify_interval == bigipconfigdriver.DEFAULT_VERIFY_INTERVAL
        assert level == logging.ERROR

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['bigip'] = {'username': 'admin', 'password': 'changeme',
                        'url': 'http://10.10.10.10:443',
                        'partitions': ['common', 'velcro']}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        try:
            host, port = bigipconfigdriver._handle_bigip_config(r)
            assert host == '10.10.10.10'
            assert port == 443
        except:
            assert 0

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config_missing_bigip(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_bigip_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config_missing_username(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['bigip'] = {'password': 'changeme',
                        'url': 'http://10.10.10.10:443',
                        'partitions': ['common', 'velcro']}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_bigip_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config_missing_password(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['bigip'] = {'username': 'admin',
                        'url': 'http://10.10.10.10:443',
                        'partitions': ['common', 'velcro']}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_bigip_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config_missing_url(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['bigip'] = {'username': 'admin', 'password': 'changeme',
                        'partitions': ['common', 'velcro']}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_bigip_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_bigip_config_missing_partitions(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['bigip'] = {'username': 'admin', 'password': 'changeme',
                        'url': 'http://10.10.10.10:443',
                        'partitions': []}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_bigip_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_vxlan_config(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['vxlan-fdb'] = {'name': 'vxlan0',
                            'records': [
                                {'name': '0a:0a:ac:10:1:5',
                                 'endpoint': '198.162.0.1'},
                                {'name': '0a:0a:ac:10:1:6',
                                 'endpoint': '198.162.0.2'}
                            ]}
        obj['vxlan-arp'] = {'arps': [
                                {'macAddress': '0a:0a:ac:10:1:5',
                                 'ipAddress': '1.2.3.4',
                                 'name': '1.2.3.4'}
                                ]
                            }

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        try:
            bigipconfigdriver._handle_vxlan_config(r)
        except:
            assert 0

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_vxlan_config_missing_vxlan_name(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['vxlan-fdb'] = {'records': [
                                {'name': '0a:0a:ac:10:1:5',
                                 'endpoint': '198.162.0.1'},
                                {'name': '0a:0a:ac:10:1:6',
                                 'endpoint': '198.162.0.2'}
                            ]}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_vxlan_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_handle_vxlan_config_missing_vxlan_records(request):
    handler = None
    try:
        mgr = MockMgr()
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, mgr, 30)

        obj = {}
        obj['vxlan-fdb'] = {'name': 'vxlan0'}

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        r = bigipconfigdriver._parse_config(config_file)
        with pytest.raises(bigipconfigdriver.ConfigError):
            bigipconfigdriver._handle_vxlan_config(r)
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def _raise_value_error():
    raise ValueError('No JSON object could be decoded', 0)


def test_confighandler_reset_json_error(request):
    exception = _raise_value_error
    common_confighandler_reset(request, exception)


def _raise_cccl_error():
    raise F5CcclValidationError('Generic CCCL Error')


def test_confighandler_reset_validation_error(request):
    exception = _raise_cccl_error
    common_confighandler_reset(request, exception)


def _raise_unexpected_error():
    raise Exception('Unexpected Failure')


def test_confighandler_reset_unexpected_error(request):
    exception = _raise_unexpected_error
    common_confighandler_reset(request, exception)


def common_confighandler_reset(request, exception):
    handler = None
    mgr = None
    flags = {'valid_interval_state': True}

    try:
        # Force an error on the fourth invocation, verify interval timer
        # is disabled during retries
        def handle_results():
            if mgr.calls == 4:
                # turn on retries by returning an error
                exception()

            valid_interval_state = flags['valid_interval_state']
            if mgr.calls == 1 or mgr.calls == 5:
                # verify interval timer is off due to previous error
                if valid_interval_state:
                    valid_interval_state =\
                        (handler._interval.is_running() is False)
            else:
                if valid_interval_state:
                    valid_interval_state =\
                        (handler._interval.is_running() is True)
            flags['valid_interval_state'] = valid_interval_state

        event = threading.Event()
        mgr = MockMgr(notify_event=event, notify_after=5,
                      handle_results=handle_results)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        # keep the interval timer from expiring during retries
        interval_time = 0.6
        handler = bigipconfigdriver.ConfigHandler(config_file, [mgr],
                                                  interval_time)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert mgr.calls == 0

        obj = deepcopy(_cloud_config)
        obj['global']['verify-interval'] = interval_time
        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        assert handler._thread.is_alive() is True

        handler.notify_reset()
        time.sleep(0.1)
        assert mgr.calls == 1
        assert flags['valid_interval_state'] is True

        handler.notify_reset()
        time.sleep(0.1)
        assert mgr.calls == 2
        assert flags['valid_interval_state'] is True

        handler.notify_reset()
        time.sleep(0.1)
        assert mgr.calls == 3
        assert flags['valid_interval_state'] is True

        # in the failure case, the exception will be caught
        # and the backoff_timer will be set.  Verify the
        # backoff time has doubled.
        handler._backoff_time = 0.6

        handler.notify_reset()
        time.sleep(0.1)
        assert mgr.calls == 4
        assert flags['valid_interval_state'] is True

        assert handler._backoff_time == 1.2
        assert handler._backoff_timer is not None

        assert handler._interval.is_running() is False

        handler.notify_reset()
        time.sleep(0.1)
        event.wait(30)
        assert event.is_set() is True
        assert flags['valid_interval_state'] is True

        # After a successful call, we should be back to using the
        # interval timer
        assert handler._backoff_time == 1
        assert handler._backoff_timer is None

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_confighandler_execution(request):
    handler = None
    try:
        # Each execution of the regenerate_config_f5() should take as
        # long as the interval timer to verify we adjust for this.
        interval_time = 0.20

        def handle_results():
            time.sleep(interval_time)

        mgr = MockMgr(handle_results=handle_results)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        # make the interval timer the same as the execution time
        handler = bigipconfigdriver.ConfigHandler(config_file, [mgr],
                                                  interval_time)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert mgr.calls == 0

        obj = deepcopy(_cloud_config)
        obj['global']['verify-interval'] = interval_time
        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(obj, f)

        assert handler._thread.is_alive() is True

        # The time spent in the execution of the regenerate_config_f5() should
        # not delay the next interval.  So we expect to have at least
        # 'total_time / interval' number of calls.
        total_time = 1.00
        # If we didn't account for execution time, we'd get about 50% of
        # the expected, so we'll use 75% to account for clock slop.
        min_expected_calls = int(0.75 * total_time / interval_time)
        handler.notify_reset()
        time.sleep(total_time)
        assert mgr.calls >= min_expected_calls

    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False


def test_confighandler_checkpoint(request):
    handler = None
    try:
        event = threading.Event()
        mgr = MockMgr(notify_event=event, notify_after=5)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, [mgr],
                                                  0.25)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert mgr.calls == 0

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(_cloud_config, f)

        assert handler._thread.is_alive() is True

        assert handler._interval.is_running() is False
        handler.notify_reset()
        time.sleep(0.2)
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
        event = threading.Event()
        mgr = MockMgr(fail=True, notify_event=event, notify_after=5)
        config_template = Template('/tmp/config.$pid')
        config_file = config_template.substitute(pid=os.getpid())

        handler = bigipconfigdriver.ConfigHandler(config_file, [mgr],
                                                  0.25)
        # give the thread an opportunity to spin up
        time.sleep(0)

        assert mgr.calls == 0

        with open(config_file, 'w+') as f:
            def fin():
                os.unlink(config_file)
            request.addfinalizer(fin)
            json.dump(_cloud_config, f)

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
        time.sleep(0.2)

        # should be false here because an invalid config stops the interval
        assert handler._interval.is_running() is False
    finally:
        assert handler is not None

        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False
        assert handler._interval.is_running() is False


def test_confighandler_backoff_time(request):
    try:
        handler = bigipconfigdriver.ConfigHandler({}, {}, 0.25)
        backoff = handler.handle_backoff
        handler._backoff_time = .025
        handler._max_backoff_time = .1

        backoff()
        # first call doubles _backoff_time _backoff_timer should have original
        # value for its interval
        assert handler._backoff_timer.interval == .025
        assert handler._backoff_time == .05
        backoff()
        # values should not change since we already have a timer set
        assert handler._backoff_timer.interval == .025
        assert handler._backoff_time == .05
        handler._backoff_timer = None
        backoff()
        # call doubles _backoff_time since we cleared previous timer
        assert handler._backoff_timer.interval == .05
        assert handler._backoff_time == .1
        handler._backoff_timer = None
        backoff()
        # hit _max_backoff_time so _backoff_time does not increase
        assert handler._backoff_timer.interval == .1
        assert handler._backoff_time == .1

    finally:
        handler.stop()
        handler._thread.join(30)
        assert handler._thread.is_alive() is False
        assert handler._interval.is_running() is False


class MockApplyConfigMgr(bigipconfigdriver.CloudServiceManager):

    def __init__(self, returns):
        self._returns = returns
        self._schema = None

    def _apply_ltm_config(self, cfg):
        return self._apply_config(cfg)

    def _apply_net_config(self, cfg):
        return self._apply_config(cfg)

    def _apply_config(self, cfg):
        val = self._returns.pop(0)
        if type(val) is 'exceptions.Exception':
            raise val
        else:
            return val

    def get_partition(self):
        return 'test'


def test_confighandler_backoff_timer(request):
    SLEEP_INTERVAL = 0.1
    INTERVAL = 5
    TEST_VECTORS = [
        [1, 0, 2, 3, 4]
    ]

    config_template = Template('/tmp/config.$pid')
    config_file = config_template.substitute(pid=os.getpid())
    obj = deepcopy(_cloud_config)
    obj['global']['verify-interval'] = INTERVAL
    with open(config_file, 'w+') as f:
        def fin():
            os.unlink(config_file)
        request.addfinalizer(fin)
        json.dump(obj, f)

    for vector in TEST_VECTORS:
        try:
            mgr = MockApplyConfigMgr(vector)

            handler = bigipconfigdriver.ConfigHandler(
                config_file, [mgr], INTERVAL
            )
            time.sleep(SLEEP_INTERVAL)

            assert handler._thread.is_alive() is True

            # regenerate_config_f5 had an error so create a backoff timer
            # with an arbitrary backoff time.
            handler._backoff_time = 64
            handler.notify_reset()
            time.sleep(SLEEP_INTERVAL)
            assert handler._backoff_timer.interval == 64
            assert handler._backoff_timer.finished.is_set() is False
            prev_timer = handler._backoff_timer

            # regenerate_config_f5 did not have an error on reconfig so we
            # should cancel and cleanup backoff timer.
            handler.notify_reset()
            time.sleep(SLEEP_INTERVAL)
            assert handler._backoff_timer is None
            assert prev_timer.finished.is_set() is True

            # regenerate_config_f5 had an error on reconfig so create a new
            # backoff timer with another arbitrary backoff time.
            handler._backoff_time = 0.5
            handler.notify_reset()
            time.sleep(SLEEP_INTERVAL)
            assert handler._backoff_timer.interval == 0.5
            assert handler._backoff_timer.finished.is_set() is False
            prev_timer = handler._backoff_timer

            # regenerate_config_f5 had another error on reconfig but there is
            # already a backoff timer so do not create a new backoff timer.
            handler.notify_reset()
            time.sleep(SLEEP_INTERVAL)
            assert handler._backoff_timer.interval == 0.5
            assert handler._backoff_timer.finished.is_set() is False
            assert handler._backoff_timer is prev_timer

            # Let the back off timer play out and call its cb resetting the
            # timer reference and calling notify_reset. regenerate_config_f5
            # will have had an error so a new timer should be created.
            handler._backoff_time = 32
            time.sleep(0.6)
            assert handler._backoff_timer.interval == 32
            assert handler._backoff_timer.finished.is_set() is False
            assert handler._backoff_timer is not prev_timer

        finally:
            handler.stop()
            handler._thread.join(30)
            assert handler._thread.is_alive() is False
            assert handler._interval.is_running() is False
