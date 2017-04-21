#!/usr/bin/env python

# Copyright 2016, 2017 F5 Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import fcntl
import hashlib
import json
import logging
import os
import os.path
import sys
import time
import threading
import signal
import urllib

import pyinotify

from urlparse import urlparse
from _f5 import CloudBigIP, get_protocol, has_partition, log_sequence
from common import extract_partition_and_name, ipv4_to_mac,\
    list_diff_exclusive, IPV4FormatError, PartitionNameError

log = logging.getLogger(__name__)
console = logging.StreamHandler()
console.setFormatter(
    logging.Formatter("[%(asctime)s %(name)s %(levelname)s] %(message)s"))
root_logger = logging.getLogger()
root_logger.addHandler(console)


DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_VERIFY_INTERVAL = 30.0


class K8sCloudBigIP(CloudBigIP):
    """K8sCloudBigIP class.

    Generates a configuration for a BigIP based upon the apps/tasks managed
    by services/pods/nodes in Kubernetes.

    - Matches apps/sevices by BigIP partition
    - Creates a Virtual Server and pool for each service type that matches a
      BigIP partition
    - For each backend (task, node, or pod), it creates a pool member and adds
      the member to the pool
    - If the app has a Marathon Health Monitor configured, create a
      corresponding health monitor for the BigIP pool member
    - Token-based authentication is used by specifying a token named 'tmos'.
      This will allow non-admin users to use the API (BIG-IP must configure
      the accounts with proper permissions, for either local or remote auth).

    Args:
        hostname: IP address of BIG-IP
        username: BIG-IP username
        password: BIG-IP password
        partitions: List of BIG-IP partitions to manage
    """

    def __init__(self, hostname, port, username, password, partitions):
        """Initialize the K8sCloudBigIP object."""
        super(K8sCloudBigIP, self).__init__(hostname, port, username,
                                            password, partitions)

    def _apply_config(self, config):
        """Apply the configuration to the BIG-IP.

        Args:
            config: BIG-IP config dict
        """
        if 'ltm' in config:
            CloudBigIP._apply_config(self, config['ltm'])
        if 'network' in config:
            self._apply_network_config(config['network'])

    def _apply_network_config(self, config):
        """Apply the network configuration to the BIG-IP.

        Args:
            config: BIG-IP network config dict
        """
        if 'fdb' in config:
            self._apply_network_fdb_config(config['fdb'])

    def _apply_network_fdb_config(self, fdb_config):
        """Apply the network fdb configuration to the BIG-IP.

        Args:
            config: BIG-IP network fdb config dict
        """
        req_vxlan_name = fdb_config['vxlan-name']
        req_fdb_record_endpoint_list = fdb_config['vxlan-node-ips']
        try:
            f5_fdb_record_endpoint_list = self.get_fdb_records(req_vxlan_name)

            log_sequence('req_fdb_record_list', req_fdb_record_endpoint_list)
            log_sequence('f5_fdb_record_list', f5_fdb_record_endpoint_list)

            # See if the list of records is different.
            # If so, update with new list.
            if list_diff_exclusive(f5_fdb_record_endpoint_list,
                                   req_fdb_record_endpoint_list):
                self.fdb_records_update(req_vxlan_name,
                                        req_fdb_record_endpoint_list)
        except (PartitionNameError, IPV4FormatError) as e:
            log.error(e)
            return
        except Exception as e:
            log.error('Failed to configure the FDB for VxLAN tunnel '
                      '{}: {}'.format(req_vxlan_name, e))

    def get_vxlan_tunnel(self, vxlan_name):
        """Get a vxlan tunnel object.

        Args:
            vxlan_name: Name of the vxlan tunnel
        """
        partition, name = extract_partition_and_name(vxlan_name)
        vxlan_tunnel = self.net.fdb.tunnels.tunnel.load(
            partition=partition, name=urllib.quote(name))
        return vxlan_tunnel

    def get_fdb_records(self, vxlan_name):
        """Get a list of FDB records (just the endpoint list) for the vxlan.

        Args:
            vxlan_name: Name of the vxlan tunnel
        """
        endpoint_list = []
        vxlan_tunnel = self.get_vxlan_tunnel(vxlan_name)
        if hasattr(vxlan_tunnel, 'records'):
            for record in vxlan_tunnel.records:
                endpoint_list.append(record['endpoint'])

        return endpoint_list

    def fdb_records_update(self, vxlan_name, endpoint_list):
        """Update the fdb records for a vxlan tunnel.

        Args:
            vxlan_name: Name of the vxlan tunnel
            fdb_record_list: IP address associated with the fdb record
        """
        vxlan_tunnel = self.get_vxlan_tunnel(vxlan_name)
        data = {'records': []}
        records = data['records']
        for endpoint in endpoint_list:
            record = {'name': ipv4_to_mac(endpoint), 'endpoint': endpoint}
            records.append(record)
        log.debug("Updating records for vxlan tunnel {}: {}".format(
            vxlan_name, data['records']))
        vxlan_tunnel.update(**data)


class IntervalTimerError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


class IntervalTimer(object):
    def __init__(self, interval, cb):
        float(interval)
        if 0 >= interval:
            raise IntervalTimerError("interval must be greater than 0")

        if not cb or not callable(cb):
            raise IntervalTimerError("cb must be callable object")

        self._cb = cb
        self._interval = interval
        self._execution_time = 0.0
        self._running = False
        self._timer = None
        self._lock = threading.RLock()

    def _set_execution_time(self, start_time, stop_time):
        if stop_time >= start_time:
            self._execution_time = stop_time - start_time
        else:
            self._execution_time = 0.0

    def _adjust_interval(self):
        adjusted_interval = self._interval - self._execution_time
        if adjusted_interval < 0.0:
            adjusted_interval = 0.0
        self._execution_time = 0.0
        return adjusted_interval

    def _run(self):
        start_time = time.clock()
        try:
            self._cb()
        except Exception:
            log.exception('Unexpected error')
        finally:
            with self._lock:
                stop_time = time.clock()
                self._set_execution_time(start_time, stop_time)
                if self._running:
                    self.start()

    def is_running(self):
        return self._running

    def start(self):
        with self._lock:
            if self._running:
                # restart timer, possibly with a new interval
                self.stop()
            self._timer = threading.Timer(self._adjust_interval(), self._run)
            # timers can't be stopped, cancel just prevents the callback from
            # occuring when the timer finally expires.  Make it a daemon allows
            # cancelled timers to exit eventually without a need for join.
            self._timer.daemon = True
            self._timer.start()
            self._running = True

    def stop(self):
        with self._lock:
            if self._running:
                self._timer.cancel()
                self._timer = None
                self._running = False


class ConfigError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)


def create_config_kubernetes(bigip, config):
    """Create a BIG-IP configuration from the Kubernetes configuration.

    Args:
        config: Kubernetes BigIP config
    """
    log.debug("Generating config for BIG-IP from Kubernetes state")
    f5 = {'ltm': {}, 'network': {}}
    if 'openshift-sdn' in config:
        f5['network'] = create_network_config_kubernetes(config)
    if 'services' in config:
        f5['ltm'] = create_ltm_config_kubernetes(bigip, config)

    return f5


def create_network_config_kubernetes(config):
    """Create a BIG-IP Network configuration from the Kubernetes config.

    Args:
        config: Kubernetes BigIP config which contains openshift-sdn defs
    """
    f5_network = {}
    if 'openshift-sdn' in config:
        openshift_sdn = config['openshift-sdn']
        f5_network['fdb'] = openshift_sdn
    return f5_network


def create_ltm_config_kubernetes(bigip, config):
    """Create a BIG-IP LTM configuration from the Kubernetes configuration.

    Args:
        config: Kubernetes BigIP config which contains a svc list
    """
    f5_services = {}

    # partitions this script is responsible for:
    partitions = frozenset(bigip.get_partitions())

    svcs = config['services']
    for svc in svcs:
        f5_service = {}

        backend = svc['virtualServer']['backend']
        frontend = svc['virtualServer']['frontend']
        health_monitors = backend.get('healthMonitors', [])

        # Only handle application if it's partition is one that this script
        # is responsible for
        if not has_partition(partitions, frontend['partition']):
            continue

        # No address for this port
        if (('virtualAddress' not in frontend or
                'bindAddr' not in frontend['virtualAddress']) and
                'iapp' not in frontend):
            log.debug("Creating pool only for %s",
                      frontend['virtualServerName'])
        elif ('iapp' not in frontend and 'bindAddr' not in
                frontend['virtualAddress']):
            continue

        frontend_name = frontend['virtualServerName']

        f5_service['name'] = frontend_name

        f5_service['partition'] = frontend['partition']

        if 'iapp' in frontend:
            f5_service['iapp'] = {'template': frontend['iapp'],
                                  'poolMemberTable':
                                  frontend['iappPoolMemberTable'],
                                  'variables': frontend['iappVariables'],
                                  'options': frontend['iappOptions']}
            f5_service['iapp']['tables'] = frontend.get('iappTables', {})
        else:
            f5_service['virtual'] = {}
            f5_service['pool'] = {}
            f5_service['health'] = []

            # Parse the SSL profile into partition and name
            profiles = []
            if 'sslProfile' in frontend:
                profile = (
                    frontend['sslProfile']['f5ProfileName'].split('/'))
                if len(profile) != 2:
                    log.error("Could not parse partition and name from "
                              "SSL profile: %s",
                              frontend['sslProfile']['f5ProfileName'])
                else:
                    profiles.append({'partition': profile[0],
                                     'name': profile[1]})

            # Add appropriate profiles
            if str(frontend['mode']).lower() == 'http':
                profiles.append({'partition': 'Common', 'name': 'http'})
            elif get_protocol(frontend['mode']) == 'tcp':
                profiles.append({'partition': 'Common', 'name': 'tcp'})

            if ('virtualAddress' in frontend and
                    'bindAddr' in frontend['virtualAddress']):
                f5_service['virtual_address'] = \
                    frontend['virtualAddress']['bindAddr']

                f5_service['virtual'].update({
                    'enabled': True,
                    'disabled': False,
                    'ipProtocol': get_protocol(frontend['mode']),
                    'destination':
                    "/%s/%s:%d" % (frontend['partition'],
                                   frontend['virtualAddress']['bindAddr'],
                                   frontend['virtualAddress']['port']),
                    'pool': "/%s/%s" % (frontend['partition'], frontend_name),
                    'sourceAddressTranslation': {'type': 'automap'},
                    'profiles': profiles
                })

            monitors = None
            # Health Monitors
            for index, health in enumerate(health_monitors):
                log.debug("Healthcheck for service %s: %s",
                          backend['serviceName'], health)
                if index == 0:
                    health['name'] = frontend_name
                else:
                    health['name'] = frontend_name + '_' + str(index)
                    monitors = monitors + ' and '
                f5_service['health'].append(health)

                # monitors is a string of health-monitor names
                # delimited by ' and '
                monitor = "/%s/%s" % (frontend['partition'],
                                      f5_service['health'][index]['name'])

                monitors = (monitors + monitor) if monitors is not None \
                    else monitor

            f5_service['pool'].update({
                'monitor': monitors,
                'loadBalancingMode': frontend['balance']
            })

        f5_service['nodes'] = {}
        if backend['poolMemberAddrs']:
            for node in backend['poolMemberAddrs']:
                f5_service['nodes'].update({node: {
                    'state': 'user-up',
                    'session': 'user-enabled'
                }})
        else:
            log.warning(
                'Virtual server "{}" has service "{}", which is empty - '
                'configuring 0 pool members.'.format(
                    frontend_name, backend['serviceName']))

        f5_services.update({frontend_name: f5_service})

    return f5_services


class ConfigHandler():
    def __init__(self, config_file, bigip, verify_interval):
        self._config_file = config_file
        self._bigip = bigip

        self._condition = threading.Condition()
        self._thread = threading.Thread(target=self._do_reset)
        self._pending_reset = False
        self._stop = False
        self._backoff_timer = 1
        self._max_backoff_time = 128

        self._interval = None
        self._verify_interval = 0
        self.set_interval_timer(verify_interval)

        self._thread.start()

    def set_interval_timer(self, verify_interval):
        if verify_interval != self._verify_interval:
            if self._interval is not None:
                self._interval.stop()
                self._interval = None

            self._verify_interval = verify_interval
            if self._verify_interval > 0:
                self._interval = IntervalTimer(self._verify_interval,
                                               self.notify_reset)

    def stop(self):
        self._condition.acquire()
        self._stop = True
        self._condition.notify()
        self._condition.release()

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
                if not self._pending_reset and not self._stop:
                    self._condition.wait()
                log.debug('config handler woken for reset')

                self._pending_reset = False
                self._condition.release()

                if self._stop:
                    log.info('stopping config handler')
                    break

                try:
                    start_time = time.time()

                    config = _parse_config(self._config_file)
                    verify_interval, _ = _handle_global_config(config)
                    _handle_openshift_sdn_config(config)
                    self.set_interval_timer(verify_interval)
                    cfg = create_config_kubernetes(self._bigip, config)
                    if self._bigip.regenerate_config_f5(cfg):
                        # Error occurred, perform retries
                        log.warning(
                            'regenerate operation failed, restarting')

                        if (self._interval and self._interval.is_running() is
                                True):
                            self._interval.stop()
                        self.retry_backoff(self.notify_reset)
                    else:
                        if (self._interval and self._interval.is_running() is
                                False):
                            self._interval.start()
                        self._backoff_timer = 1

                        perf_enable = os.environ.get('SCALE_PERF_ENABLE')
                        if perf_enable:  # pragma: no cover
                            test_data = {}
                            app_count = 0
                            backend_count = 0
                            for service in config['services']:
                                app_count += 1
                                vs_bkend = service['virtualServer']['backend']
                                backends = len(vs_bkend['poolMemberAddrs'])
                                test_data[vs_bkend['serviceName']] = backends
                                backend_count += backends
                            test_data['Total_Services'] = app_count
                            test_data['Total_Backends'] = backend_count
                            test_data['Time'] = time.time()
                            json_data = json.dumps(test_data)
                            log.info('SCALE_PERF: Test data: %s', json_data)

                    log.debug('updating tasks finished, took %s seconds',
                              time.time() - start_time)
                except Exception:
                    log.exception('Unexpected error')

        if self._interval:
            self._interval.stop()

    def retry_backoff(self, func):
        """Add a backoff timer to retry in case of failure."""
        e = threading.Event()
        log.error("Error applying config, will try again in %s seconds",
                  self._backoff_timer)
        e.wait(self._backoff_timer)
        if self._backoff_timer < self._max_backoff_time:
            self._backoff_timer *= 2
        func()


class ConfigWatcher(pyinotify.ProcessEvent):
    def __init__(self, config_file, bigip, on_change):
        basename = os.path.basename(config_file)
        if not basename or 0 == len(basename):
            raise ConfigError('config_file must be a file path')

        self._config_file = config_file
        self._bigip = bigip
        self._on_change = on_change

        self._config_dir = os.path.dirname(self._config_file)
        self._config_stats = None
        if os.path.exists(self._config_file):
            try:
                self._config_stats = self._md5()
            except IOError as ioe:
                log.warning('ioerror during md5 sum calculation: {}'.
                            format(ioe))

        self._running = False
        self._polling = False
        self._user_abort = False
        signal.signal(signal.SIGINT, self._exit_gracefully)
        signal.signal(signal.SIGTERM, self._exit_gracefully)

    def _exit_gracefully(self, signum, frame):
        self._user_abort = True
        self._running = False

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
            except Exception as e:
                log.warning(e)

        if self._user_abort:
            log.info('Received user kill signal, terminating.')

    def _md5(self):
        md5 = hashlib.md5()

        with open(self._config_file, 'rb') as f:
            fcntl.lockf(f.fileno(), fcntl.LOCK_SH, 0, 0, 0)
            while True:
                buf = f.read(4096)
                if not buf:
                    break
                md5.update(buf)
            fcntl.lockf(f.fileno(), fcntl.LOCK_UN, 0, 0, 0)
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
            try:
                cur_hash = self._md5()
                if cur_hash != self._config_stats:
                    changed = True
                else:
                    changed = False
            except IOError as ioe:
                log.warning('ioerror during md5 sum calculation: {}'.
                            format(ioe))

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


def _parse_config(config_file):
    if os.path.exists(config_file):
        with open(config_file, 'r') as config:
            fcntl.lockf(config.fileno(), fcntl.LOCK_SH, 0, 0, 0)
            config_json = json.load(config)
            fcntl.lockf(config.fileno(), fcntl.LOCK_UN, 0, 0, 0)
            log.debug('loaded configuration file successfully')
            return config_json
    else:
        return None


def _handle_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
            '--config-file',
            type=str,
            required=True,
            help='BigIp configuration file')
    args = parser.parse_args()

    basename = os.path.basename(args.config_file)
    if not basename or 0 == len(basename):
        raise ConfigError('must provide a file path')

    args.config_file = os.path.realpath(args.config_file)

    return args


def _handle_global_config(config):
    level = DEFAULT_LOG_LEVEL
    verify_interval = DEFAULT_VERIFY_INTERVAL

    if config and 'global' in config:
        global_cfg = config['global']

        if 'log-level' in global_cfg:
            log_level = global_cfg['log-level']
            try:
                level = logging.getLevelName(log_level.upper())
            except (AttributeError):
                log.warn('The "global:log-level" field in the configuration '
                         'file should be a string')

        if 'verify-interval' in global_cfg:
            try:
                verify_interval = float(global_cfg['verify-interval'])
                if verify_interval < 0:
                    verify_interval = DEFAULT_VERIFY_INTERVAL
                    log.warn('The "global:verify-interval" field in the '
                             'configuration file should be a non-negative '
                             'number')
            except (ValueError):
                log.warn('The "global:verify-interval" field in the '
                         'configuration file should be a number')

    try:
        root_logger.setLevel(level)
        if level > logging.DEBUG:
            logging.getLogger('requests.packages.urllib3.'
                              'connectionpool').setLevel(logging.WARNING)
    except:
        level = DEFAULT_LOG_LEVEL
        root_logger.setLevel(level)
        if level > logging.DEBUG:
            logging.getLogger('requests.packages.urllib3.'
                              'connectionpool').setLevel(logging.WARNING)
        log.warn('Undefined value specified for the '
                 '"global:log-level" field in the configuration file')

    # level only is needed for unit tests
    return verify_interval, level


def _handle_bigip_config(config):
    if (not config) or ('bigip' not in config):
        raise ConfigError('Configuration file missing "bigip" section')
    bigip = config['bigip']
    if 'username' not in bigip:
        raise ConfigError('Configuration file missing '
                          '"bigip:username" section')
    if 'password' not in bigip:
        raise ConfigError('Configuration file missing '
                          '"bigip:password" section')
    if 'url' not in bigip:
        raise ConfigError('Configuration file missing "bigip:url" section')
    if ('partitions' not in bigip) or (len(bigip['partitions']) == 0):
        raise ConfigError('Configuration file must specify at least one '
                          'partition in the "bigip:partitions" section')

    url = urlparse(bigip['url'])
    host = url.hostname
    port = url.port
    if not port:
        port = 443

    return host, port


def _handle_openshift_sdn_config(config):
    if config and 'openshift-sdn' in config:
        sdn = config['openshift-sdn']
        if 'vxlan-name' not in sdn:
            raise ConfigError('Configuration file missing '
                              '"openshift-sdn:vxlan-name" section')
        if 'vxlan-node-ips' not in sdn:
            raise ConfigError('Configuration file missing '
                              '"openshift-sdn:vxlan-node-ips" section')


def main():
    try:
        args = _handle_args()

        config = _parse_config(args.config_file)
        verify_interval, _ = _handle_global_config(config)
        host, port = _handle_bigip_config(config)

        # FIXME (kenr): Big-IP settings are currently static (we ignore any
        #               changes to these fields in subsequent updates). We
        #               may want to make the changes dynamic in the future.
        bigip = K8sCloudBigIP(host, port,
                              config['bigip']['username'],
                              config['bigip']['password'],
                              config['bigip']['partitions'])

        handler = ConfigHandler(args.config_file, bigip, verify_interval)

        if os.path.exists(args.config_file):
            handler.notify_reset()

        watcher = ConfigWatcher(args.config_file, bigip, handler.notify_reset)
        watcher.loop()
        handler.stop()
    except (IOError, ValueError, ConfigError) as e:
        log.error(e)
        sys.exit(1)
    except Exception:
        log.exception('Unexpected error')
        sys.exit(1)

    return 0


if __name__ == "__main__":
    main()
