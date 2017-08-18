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
from __future__ import absolute_import

import argparse
import fcntl
import hashlib
import ipaddress
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
from f5.bigip import ManagementRoot
from f5_cccl.api import F5CloudServiceManager
from f5_cccl.exceptions import F5CcclError

log = logging.getLogger(__name__)
console = logging.StreamHandler()
console.setFormatter(
    logging.Formatter("[%(asctime)s %(name)s %(levelname)s] %(message)s"))
root_logger = logging.getLogger()
root_logger.addHandler(console)

SCHEMA_PATH = "./src/f5-cccl/f5_cccl/schemas/cccl-api-schema.yml"


class PartitionNameError(Exception):
    """Exception type for F5 resource name."""

    def __init__(self, msg):
        """Create partition name exception object."""
        Exception.__init__(self, msg)


class IPV4FormatError(Exception):
    """Exception type for improperly formatted IPv4 address."""

    def __init__(self, msg):
        """Create ipv4 format exception object."""
        Exception.__init__(self, msg)


class ResponseStatusFilter(logging.Filter):
    def filter(self, record):
        return not record.getMessage().startswith("RESPONSE::STATUS")


class CertFilter(logging.Filter):
    def filter(self, record):
        return "CERTIFICATE" not in record.getMessage()


class KeyFilter(logging.Filter):
    def filter(self, record):
        return "PRIVATE KEY" not in record.getMessage()


root_logger.addFilter(ResponseStatusFilter())
root_logger.addFilter(CertFilter())
root_logger.addFilter(KeyFilter())


def list_diff_exclusive(list1, list2):
    """Return items found only in list1 or list2."""
    return list(set(list1) ^ set(list2))


def ipv4_to_mac(ip_str):
    """Convert an IPV4 string to a fake MAC address."""
    ip = ip_str.split('.')
    if len(ip) != 4:
        raise IPV4FormatError('Bad IPv4 address format specified for '
                              'FDB record: {}'.format(ip_str))

    return "0a:0a:%02x:%02x:%02x:%02x" % (
        int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))


def extract_partition_and_name(f5_partition_name):
    """Separate partition and name components for a Big-IP resource."""
    parts = f5_partition_name.split('/')
    count = len(parts)
    if f5_partition_name[0] == '/' and count == 3:
        # leading slash
        partition = parts[1]
        name = parts[2]
    elif f5_partition_name[0] != '/' and count == 2:
        # leading slash missing
        partition = parts[0]
        name = parts[1]
    else:
        raise PartitionNameError('Bad F5 resource name encountered: '
                                 '{}'.format(f5_partition_name))
    return partition, name


def log_sequence(prefix, sequence_to_log):
    """Helper function to log a sequence.

    Dump a sequence to the logger, skip if it is empty

    Args:
        prefix: The prefix string to describe what's being logged
        sequence_to_log: The sequence being logged
    """
    if sequence_to_log:
        log.debug(prefix + ': %s', (', '.join(sequence_to_log)))


def get_protocol(protocol):
    """Return the protocol (tcp or udp)."""
    if str(protocol).lower() == 'tcp':
        return 'tcp'
    if str(protocol).lower() == 'http':
        return 'tcp'
    if str(protocol).lower() == 'udp':
        return 'udp'
    else:
        return None


DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_VERIFY_INTERVAL = 30.0


class K8sCloudServiceManager():
    """K8sCloudServiceManager class.

    Generates a configuration for a BigIP based upon the apps/tasks managed
    by services/pods/nodes in Kubernetes.

    - Matches apps/sevices by BigIP partition
    - Creates a Virtual Server and pool for each service type that matches a
      BigIP partition
    - For each backend (task, node, or pod), it creates a pool member and adds
      the member to the pool
    - Token-based authentication is used by specifying a token named 'tmos'.
      This will allow non-admin users to use the API (BIG-IP must configure
      the accounts with proper permissions, for either local or remote auth).

    Args:
        bigip: ManagementRoot object
        partition: BIG-IP partition to manage
        schema_path: Path to the CCCL schema
    """

    def __init__(self, bigip, partition, schema_path):
        """Initialize the K8sCloudServiceManager object."""
        self._mgmt_root = bigip
        self._cccl = F5CloudServiceManager(
            bigip,
            partition,
            prefix="",
            schema_path=schema_path)

    def mgmt_root(self):
        """ Return the BIG-IP ManagementRoot object"""
        return self._mgmt_root

    def get_partition(self):
        """ Return the managed partition."""
        return self._cccl.get_partition()

    def _apply_config(self, config):
        """Apply the configuration to the BIG-IP.

        Args:
            config: BIG-IP config dict
        """
        incomplete = 0
        if 'ltm' in config:
            incomplete = self._cccl.apply_config(config['ltm'])
        if 'network' in config:
            incomplete += self._apply_network_config(config['network'])

        return incomplete

    def _apply_network_config(self, config):
        """Apply the network configuration to the BIG-IP.

        Args:
            config: BIG-IP network config dict
        """
        if 'fdb' in config:
            return self._apply_network_fdb_config(config['fdb'])

        return 0

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
            return 0
        except (PartitionNameError, IPV4FormatError) as e:
            log.error(e)
            return 0
        except Exception as e:
            log.error('Failed to configure the FDB for VxLAN tunnel '
                      '{}: {}'.format(req_vxlan_name, e))
            return 1

    def get_vxlan_tunnel(self, vxlan_name):
        """Get a vxlan tunnel object.

        Args:
            vxlan_name: Name of the vxlan tunnel
        """
        partition, name = extract_partition_and_name(vxlan_name)
        vxlan_tunnel = self._mgmt_root.tm.net.fdb.tunnels.tunnel.load(
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


def create_config_kubernetes(partition, config):
    """Create a BIG-IP configuration from the Kubernetes configuration.

    Args:
        config: Kubernetes BigIP config
    """
    log.debug("Generating config for BIG-IP from Kubernetes state")
    f5 = {'ltm': {}, 'network': {}}
    if 'openshift-sdn' in config:
        f5['network'] = create_network_config_kubernetes(config)
    if 'resources' in config and 'virtualServers' in config['resources']:
        f5['ltm'] = create_ltm_config_kubernetes(partition,
                                                 config['resources'])

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


def append_ssl_profile(profiles, profName):
    profile = (profName.split('/'))
    if len(profile) != 2:
        log.error("Could not parse partition and name "
                  "from SSL profile: %s", profName)
    else:
        profiles.append({'partition': profile[0],
                         'name': profile[1]})


def create_ltm_config_kubernetes(partition, config):
    """Create a BIG-IP LTM configuration from the Kubernetes configuration.

    Args:
        config: Kubernetes BigIP config which contains a svc list
    """
    # FIXME (darzins): Move all conversion for CCCL schema to the golang
    # frontend so that we're doing conversion in one step, not two
    configuration = {
        'virtualServers': [],
        'l7Policies': [],
        'pools': [],
        'monitors': [],
        'iapps': [],
        'iRules': [],
        'internalDataGroups': []
    }

    f5_services = {}

    # reformat policies
    for policy in config.get('l7Policies', []):
        if policy.get('partition', None) == partition:
            del policy['partition']
            configuration['l7Policies'].append(policy)

    # reformat monitors
    for monitor in config.get('monitors', []):
        if monitor.get('partition', None) == partition:
            if 'protocol' in monitor:
                monitor['type'] = monitor['protocol']
                del monitor['protocol']
            del monitor['partition']

            configuration['monitors'].append(monitor)

    # reformat iRules
    for irule in config.get('iRules', []):
        if irule.get('partition', None) == partition:
            del irule['partition']
            configuration['iRules'].append(irule)

    # reformat internalDataGroups
    for idg in config.get('internalDataGroups', []):
        if idg.get('partition', None) == partition:
            del idg['partition']
            configuration['internalDataGroups'].append(idg)

    svcs = config['virtualServers']
    for svc in svcs:
        vs_partition = svc['partition']
        # Only handle application if it's partition is one that this script
        # is responsible for
        if partition != vs_partition:
            continue

        f5_service = {}
        vs_name = svc['name']

        policies = svc.get('policies', [])
        profiles = svc.get('profiles', [])

        pool = {}

        # No address for this port
        if (('virtualAddress' not in svc or
                'bindAddr' not in svc['virtualAddress']) and
                'iapp' not in svc):
            log.debug("Creating pool only for %s", vs_name)
        elif ('iapp' not in svc and 'bindAddr' not in
                svc['virtualAddress']):
            continue

        f5_service['name'] = vs_name
        f5_service['rules'] = svc.get('rules', [])

        if 'iapp' in svc:
            cfg = {'tables': {}}
            for k, v in {'template': 'iapp',
                         'poolMemberTable': 'iappPoolMemberTable',
                         'tables': 'iappTables',
                         'variables': 'iappVariables',
                         'options': 'iappOptions'}.iteritems():
                if v in svc:
                    cfg[k] = svc[v]

            members = []
            for pool in config.get('pools', []):
                if pool['name'] == f5_service['name']:
                    if 'poolMemberAddrs' in pool:
                        for member in pool['poolMemberAddrs']:
                            members.append({
                                'address': member.split(':')[0],
                                'port': int(member.split(':')[1])
                            })

            iapp = {
                'name': f5_service['name'],
                'template': cfg['template'],
                'variables': cfg['variables'],
                'tables': cfg['tables'],
                'options': cfg['options']
            }

            # Add the poolMemberTable
            if 'poolMemberTable' in cfg:
                cfg['poolMemberTable']['members'] = members
                iapp['poolMemberTable'] = cfg['poolMemberTable']

            configuration['iapps'].append(iapp)
        else:
            f5_service['pool'] = {}

            # Parse the SSL profile into partition and name
            if 'sslProfile' in svc:
                # The sslProfile item can be empty or have either
                # 'f5ProfileName' or 'f5ProfileNames', not both.
                if 'f5ProfileName' in svc['sslProfile']:
                    append_ssl_profile(
                        profiles, svc['sslProfile']['f5ProfileName'])
                elif 'f5ProfileNames' in svc['sslProfile']:
                    for profName in svc['sslProfile']['f5ProfileNames']:
                        append_ssl_profile(profiles, profName)

            # Add appropriate profiles
            profile_http = {'partition': 'Common', 'name': 'http'}
            profile_tcp = {'partition': 'Common', 'name': 'tcp'}
            if str(svc['mode']).lower() == 'http':
                if profile_http not in profiles:
                    profiles.append(profile_http)
            elif get_protocol(svc['mode']) == 'tcp':
                if profile_tcp not in profiles:
                    profiles.append(profile_tcp)

            if ('virtualAddress' in svc and
                    'bindAddr' in svc['virtualAddress']):
                f5_service['virtual_address'] = \
                    svc['virtualAddress']['bindAddr']

                addr = svc['virtualAddress']['bindAddr']
                port = svc['virtualAddress']['port']
                destination = None
                if isinstance(ipaddress.ip_address(addr),
                              ipaddress.IPv6Address):
                    destination = ("/%s/%s.%d" %
                                   (vs_partition, addr, port))
                else:
                    destination = ("/%s/%s:%d" %
                                   (vs_partition, addr, port))

                f5_service.update({
                    'enabled': True,
                    'ipProtocol': get_protocol(svc['mode']),
                    'destination': destination,
                    'pool': "%s" % (svc['pool']),
                    'sourceAddressTranslation': {'type': 'automap'},
                    'profiles': profiles,
                    'policies': policies
                })
            f5_services.update({vs_name: f5_service})

            if f5_service.get('destination', None) is not None:
                configuration['virtualServers'].append(f5_service)

    # FIXME(garyr): CCCL presently expects pools slightly differently than
    # we get from the controller, so convert to the expected format here.
    for pool in config.get('pools', []):
        found_svc = False
        new_pool = {}
        members = []
        pname = pool['name']
        new_pool['name'] = pname
        if 'monitor' in pool and pool['monitor']:
            new_pool['monitors'] = pool['monitor']
        new_pool['loadBalancingMode'] = pool['loadBalancingMode']

        # FIXME(berman): This is still very hacky until we fix the bug
        # where pools are created for iapps; this conditional ensures we create
        # pools in all cases except in the iapp case
        vname = pname.rsplit('_', 1)[0]
        if (pool['name'] in f5_services or vname in f5_services
                or pool['name'].startswith('openshift_')):
            if pool.get('poolMemberAddrs', None) is not None:
                found_svc = True
                for member in pool['poolMemberAddrs']:
                    members.append({
                        'address': member.split(':')[0],
                        'port': int(member.split(':')[1]),
                        'session': 'user-enabled'
                    })
                new_pool['members'] = members
            configuration['pools'].append(new_pool)

        if not found_svc:
            log.info(
                'Pool "{}" has service "{}", which is empty - '
                'configuring 0 pool members.'.format(
                    pname, pool['serviceName']))

    # Append the protocol to the monitor names to differentiate them.
    # Also add a monitor index to the name to be consistent with the
    # marathon-bigip-ctlr. Since the monitor names are already unique here,
    # appending a '0' is sufficient.
    for monitor in configuration.get('monitors', []):
        old_name = monitor['name']
        old_path = '/' + partition + '/' + old_name
        suffix = '_0_' + monitor['type']
        monitor['name'] += suffix

        for pool in configuration.get('pools', []):
            if 'monitors' in pool:
                pool['monitors'] = [mon + suffix if mon == old_path else mon
                                    for mon in pool['monitors']]

    log.debug("Service Config: %s", json.dumps(configuration))
    return configuration


def _create_client_ssl_profile(mgmt, profile):
    incomplete = 0

    # bigip object is of type f5.bigip.tm;
    # we need f5.bigip.shared for the uploader
    uploader = mgmt.shared.file_transfer.uploads
    cert_registrar = mgmt.tm.sys.crypto.certs
    key_registrar = mgmt.tm.sys.crypto.keys
    ssl_client_profile = mgmt.tm.ltm.profile.client_ssls.client_ssl

    name = profile['name']
    partition = profile['partition']
    cert = profile['cert']
    key = profile['key']
    serverName = profile.get('serverName', None)

    # No need to create if it exists
    if ssl_client_profile.exists(name=name, partition=partition):
        return

    certfilename = name + '.crt'
    keyfilename = name + '.key'

    try:
        # In-memory upload -- data not written to local file system but
        # is saved as a file on the BIG-IP
        uploader.upload_bytes(cert, certfilename)
        uploader.upload_bytes(key, keyfilename)

        # import certificate
        param_set = {}
        param_set['name'] = certfilename
        param_set['from-local-file'] = os.path.join(
            '/var/config/rest/downloads', certfilename)
        cert_registrar.exec_cmd('install', **param_set)

        # import key
        param_set['name'] = keyfilename
        param_set['from-local-file'] = os.path.join(
            '/var/config/rest/downloads', keyfilename)
        key_registrar.exec_cmd('install', **param_set)

        # create ssl-client profile from cert/key pair
        chain = [{'name': name,
                  'cert': '/Common/' + certfilename,
                  'key': '/Common/' + keyfilename}]
        ssl_client_profile.create(name=name,
                                  partition=partition,
                                  certKeyChain=chain,
                                  serverName=serverName,
                                  sniDefault=False,
                                  defaultsFrom=None)
    except Exception as err:
        log.error("Error creating SSL profile: %s" % err.message)
        incomplete = 1

    return incomplete


def _delete_client_ssl_profiles(mgmt, partition, config):
    incomplete = 0

    try:
        profiles = mgmt.tm.ltm.profile.client_ssls.get_collection(
            requests_params={'params': '$filter=partition+eq+%s'
                             % partition})
    except Exception as err:
        log.error("Error reading profiles from BIG-IP: %s" % err.message)
        incomplete += 1
        return incomplete

    if 'customProfiles' not in config:
        # delete any profiles in managed partition
        for prof in profiles:
            try:
                prof.delete()
            except Exception as err:
                log.error("Error deleting SSL profile: %s" % err.message)
                incomplete += 1
    else:
        # delete profiles no longer in our config
        for prof in profiles:
            if not any(d['name'] == prof.name and
                       d['partition'] == partition
                       for d in config['customProfiles']):
                try:
                    prof.delete()
                except Exception as err:
                    log.error("Error deleting SSL profile: %s" % err.message)
                    incomplete += 1

    return incomplete


class ConfigHandler():
    def __init__(self, config_file, managers, verify_interval):
        self._config_file = config_file
        self._managers = managers

        self._condition = threading.Condition()
        self._thread = threading.Thread(target=self._do_reset)
        self._pending_reset = False
        self._stop = False
        self._backoff_time = 1
        self._backoff_timer = None
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
        if self._backoff_timer is not None:
            self.cleanup_backoff()

    def notify_reset(self):
        self._condition.acquire()
        self._pending_reset = True
        self._condition.notify()
        self._condition.release()

    def _do_reset(self):
        log.debug('config handler thread start')

        with self._condition:
            # customProfiles is true when we've written out a custom profile.
            # Once we know we've written out a profile, we can call delete
            # if needed.
            customProfiles = False
            while True:
                self._condition.acquire()
                if not self._pending_reset and not self._stop:
                    self._condition.wait()
                log.debug('config handler woken for reset')

                self._pending_reset = False
                self._condition.release()

                if self._stop:
                    log.info('stopping config handler')
                    if self._backoff_timer is not None:
                        self.cleanup_backoff()
                    break

                start_time = time.time()

                config = _parse_config(self._config_file)
                # No 'resources' indicates that the controller is not
                # yet ready -- it does not mean to apply an empty config
                if 'resources' not in config:
                    continue
                verify_interval, _ = _handle_global_config(config)
                _handle_openshift_sdn_config(config)
                self.set_interval_timer(verify_interval)

                incomplete = 0

                for mgr in self._managers:
                    cfg = create_config_kubernetes(mgr.get_partition(),
                                                   config)

                    try:
                        # Manually create custom profiles;
                        # CCCL doesn't yet do this
                        if 'customProfiles' in config['resources']:
                            for profile in \
                                    config['resources']['customProfiles']:
                                if profile['partition'] == \
                                        mgr.get_partition():
                                    _create_client_ssl_profile(
                                        mgr.mgmt_root(),
                                        profile)
                                    customProfiles = True

                        # Apply the BIG-IP config after creating profiles
                        # and before deleting profiles
                        incomplete += mgr._apply_config(cfg)

                        # Manually delete custom profiles (if needed)
                        if customProfiles:
                            _delete_client_ssl_profiles(
                                mgr.mgmt_root(),
                                mgr.get_partition(),
                                config['resources'])

                    except F5CcclError as e:
                        # We created an invalid configuration, raise the
                        # exception and fail
                        log.error("CCCL Error: %s", e.msg)
                        raise e

                if incomplete:
                    # Error occurred, perform retries
                    self.handle_backoff()
                else:
                    if (self._interval and self._interval.is_running()
                            is False):
                        self._interval.start()
                    self._backoff_time = 1
                    if self._backoff_timer is not None:
                        self.cleanup_backoff()

                perf_enable = os.environ.get('SCALE_PERF_ENABLE')
                if perf_enable:  # pragma: no cover
                    test_data = {}
                    app_count = 0
                    backend_count = 0
                    for service in config['resources']['virtualServers']:
                        app_count += 1
                        backends = 0
                        for pool in config['resources']['pools']:
                            if pool['name'] == service['name']:
                                backends = len(pool['poolMemberAddrs'])
                                break
                        test_data[service['name']] = backends
                        backend_count += backends
                    test_data['Total_Services'] = app_count
                    test_data['Total_Backends'] = backend_count
                    test_data['Time'] = time.time()
                    json_data = json.dumps(test_data)
                    log.info('SCALE_PERF: Test data: %s',
                             json_data)

                log.debug('updating tasks finished, took %s seconds',
                          time.time() - start_time)

        if self._interval:
            self._interval.stop()

    def cleanup_backoff(self):
        """Cleans up canceled backoff timers."""
        self._backoff_timer.cancel()
        self._backoff_timer.join()
        self._backoff_timer = None

    def handle_backoff(self):
        """Wrapper for calls to retry_backoff."""
        if (self._interval and self._interval.is_running() is
                True):
            self._interval.stop()
        if self._backoff_timer is None:
            self.retry_backoff()

    def retry_backoff(self):
        """Add a backoff timer to retry in case of failure."""
        def timer_cb():
            self._backoff_timer = None
            self.notify_reset()

        self._backoff_timer = threading.Timer(
            self._backoff_time, timer_cb
        )
        log.error("Error applying config, will try again in %s seconds",
                  self._backoff_time)
        self._backoff_timer.start()
        if self._backoff_time < self._max_backoff_time:
            self._backoff_time *= 2


class ConfigWatcher(pyinotify.ProcessEvent):
    def __init__(self, config_file, on_change):
        basename = os.path.basename(config_file)
        if not basename or 0 == len(basename):
            raise ConfigError('config_file must be a file path')

        self._config_file = config_file
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

        # BIG-IP to manage
        bigip = ManagementRoot(
            host,
            config['bigip']['username'],
            config['bigip']['password'],
            port=port,
            token="tmos")

        k8s_managers = []
        for partition in config['bigip']['partitions']:
            # Management for the BIG-IP partitions
            manager = K8sCloudServiceManager(
                bigip,
                partition,
                schema_path=SCHEMA_PATH)
            k8s_managers.append(manager)

        handler = ConfigHandler(args.config_file,
                                k8s_managers,
                                verify_interval)

        if os.path.exists(args.config_file):
            handler.notify_reset()

        watcher = ConfigWatcher(args.config_file, handler.notify_reset)
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
