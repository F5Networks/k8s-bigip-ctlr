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
import os
import shutil
import sys
from string import Template

import pytest

import bigipconfigdriver

_args_app_name = ['bigipconfigdriver.py']
_args_too_many = ['1', '2', '3']


def test_handleargs_noargs(capsys):
    expected = \
"""usage: bigipconfigdriver.py [-h] [-v] config-file
bigipconfigdriver.py: error: too few arguments
"""

    sys.argv[0:] = _args_app_name

    with pytest.raises(SystemExit):
        bigipconfigdriver._handle_args()

    out, err = capsys.readouterr()
    assert '' == out
    assert expected == err


def test_handleargs_toomany(capsys):
    expected = \
"""usage: bigipconfigdriver.py [-h] [-v] config-file
bigipconfigdriver.py: error: unrecognized arguments: 2 3
"""

    sys.argv[0:] = _args_app_name + _args_too_many

    with pytest.raises(SystemExit):
        bigipconfigdriver._handle_args()

    out, err = capsys.readouterr()
    assert '' == out
    assert expected == err


def test_handleargs_notfilepath():
    sys.argv[0:] = _args_app_name + ['/tmp/not-a-file/']
    with pytest.raises(bigipconfigdriver.ConfigError) as eio:
        bigipconfigdriver._handle_args()

    assert eio.value.message == 'must provide a file path'


def test_handleargs_realpath():
    sys.argv[0:] = _args_app_name + ['/tmp/file/../.././tmp/.//file']

    (realpath, verbose) = bigipconfigdriver._handle_args()

    assert realpath == '/tmp/file'
    assert verbose == False


def test_handleargs_expected():
    sys.argv[0:] = _args_app_name + ['/tmp/file']

    (realpath, verbose) = bigipconfigdriver._handle_args()

    assert realpath == '/tmp/file'
    assert verbose == False


def test_handleargs_verbose():
    sys.argv[0:] = _args_app_name + ['-v', '/tmp/file']

    (realpath, verbose) = bigipconfigdriver._handle_args()

    assert realpath == '/tmp/file'
    assert verbose == True


# ConfigWatcher tests
def test_configwatcher_init(request):
    expected_dir_template = Template('/tmp/$pid')
    expected_dir = expected_dir_template.substitute(pid=os.getpid())
    expected_file = expected_dir + '/file'

    def fin():
        shutil.rmtree(expected_dir, ignore_errors=True)

    request.addfinalizer(fin)

    watcher = bigipconfigdriver.ConfigWatcher(expected_file)

    assert watcher._config_file == expected_file
    assert watcher._config_dir == expected_dir
    assert watcher._config_stats == None
    assert watcher._polling == False
    assert watcher._running == False

    # Test with file on created
    expected_digest = '\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~'

    os.mkdir(expected_dir)
    with open(expected_file, 'w+'):
        os.utime(expected_file, None)

    watcherExist = bigipconfigdriver.ConfigWatcher(expected_file)

    assert watcherExist._config_file == expected_file
    assert watcherExist._config_dir == expected_dir
    assert watcherExist._config_stats == expected_digest
    assert watcher._polling == False
    assert watcher._running == False


def test_configwatcher_shouldwatch():
    watch_file_template = Template('/tmp/$pid')
    watch_file = watch_file_template.substitute(pid=os.getpid())

    watcher = bigipconfigdriver.ConfigWatcher(watch_file)

    assert watcher._should_watch(watch_file) == True

    assert watcher._should_watch('/tmp/not-config-file') == False


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

    watcher = bigipconfigdriver.ConfigWatcher(watch_file)

    # loop will block and threading will introduce synchronization complexities
    # assuming pyinotify signals properly and only testing the _is_changed
    # function
    assert watcher._config_stats == None

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
