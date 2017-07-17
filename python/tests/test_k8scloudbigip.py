# Copyright 2017 F5 Networks
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

"""Controller Unit Tests.

Units tests for testing BIG-IP resource management in Kubernetes and OpenShift.

"""
from __future__ import absolute_import

import unittest
import json
from mock import Mock, patch
from f5.bigip import ManagementRoot
from f5_cccl.exceptions import F5CcclValidationError
from f5_cccl.exceptions import F5CcclSchemaError
from .. import bigipconfigdriver as ctlr

SCHEMA_PATH = "/go/src/f5-cccl/f5_cccl/schemas/cccl-api-schema.yml"


# Kuberentes app data
kubernetes_test_data = [
    'tests/kubernetes_one_svc_two_nodes.json',
    'tests/kubernetes_invalid_svcs.json',
    'tests/kubernetes_one_svc_one_node.json',
    'tests/kubernetes_one_svc_four_nodes.json',
    'tests/kubernetes_one_iapp.json',
    'tests/kubernetes_no_apps.json',
    'tests/kubernetes_one_svc_two_nodes_pool_only.json'
]


class IPV4FormatError(Exception):
    """Exception type for improperly formatted IPv4 address."""

    def __init__(self, msg):
        """Create ipv4 format exception object."""
        Exception.__init__(self, msg)


def ipv4_to_mac(ip_str):
    """Convert an IPV4 string to a fake MAC address."""
    ip = ip_str.split('.')
    if len(ip) != 4:
        raise IPV4FormatError('Bad IPv4 address format specified for '
                              'FDB record: {}'.format(ip_str))

    return "0a:0a:%02x:%02x:%02x:%02x" % (
        int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))


class VxLANTunnel():
    """A mock BIG-IP VxLAN tunnel."""

    def __init__(self, partition, name, initial_records):
        """Initialize the object."""
        self.partition = partition
        self.name = name
        self.records = initial_records

    def update(self, **kwargs):
        """Update list of vxlan records."""
        self.records = []
        if 'records' in kwargs:
            self.records = kwargs['records']


class KubernetesTest(unittest.TestCase):
    """Kubernetes/Big-IP configuration tests.

    Test BIG-IP configuration given various Kubernetes states and existing
    BIG-IP states
    """

    def setUp(self):
        """Test suite set up."""
        # Mock the call to _get_tmos_version(), which tries to make a
        # connection
        partition = 'k8s'
        with patch.object(ManagementRoot, '_get_tmos_version'):
            bigip = ManagementRoot('1.2.3.4', 'admin', 'default')

            self.mgr = ctlr.K8sCloudServiceManager(
                bigip,
                partition,
                schema_path=SCHEMA_PATH)

        self.cccl = self.mgr._cccl
        self.cccl._service_manager._service_deployer._bigip.refresh = Mock()
        self.cccl._service_manager._service_deployer.deploy = \
            Mock(return_value=0)

        # mock out the bigip.tm.net.fdb.tunnels.tunnel resource
        bigip.tm = type('', (), {})()
        bigip.tm.net = type('', (), {})()
        bigip.tm.net.fdb = type('', (), {})()
        bigip.tm.net.fdb.tunnels = type('', (), {})()
        bigip.tm.net.fdb.tunnels.tunnel = \
            type('', (), {})()
        bigip.tm.net.fdb.tunnels.tunnel.load = \
            Mock(side_effect=self.mock_net_fdb_tunnels_tunnel_load)

    def read_test_vectors(self, cloud_state, network_state=None):
        """Read test vectors for the various states."""
        # Read the Kubernetes state
        if cloud_state:
            with open(cloud_state) as json_data:
                self.cloud_data = json.load(json_data)

        if network_state:
            with open(network_state) as json_data:
                self.network_data = json.load(json_data)

    def mock_net_fdb_tunnels_tunnel_load(self, partition, name):
        """Mock: Get a mocked vxla tunnel to store the vxlan record config."""
        if not hasattr(self, 'vxlan_tunnel'):
            # create a BigIP resource to store the 'current' tunnel
            # FDB as well as updates.
            self.vxlan_tunnel = VxLANTunnel(partition, name, self.network_data)
        return self.vxlan_tunnel

    def verify_kubernetes_config(self, cloud_state, expected_state):
        """Test: Verify expected config created from the Kubernetes state."""
        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)

        with open(expected_state) as json_data:
                exp = json.load(json_data)
        self.assertEqual(cfg, exp)

        self.mgr._apply_config(cfg)

    def test_cccl_exceptions(
            self,
            cloud_state='tests/kubernetes_one_svc_two_nodes.json'):
        """Test: CCCL exceptions."""
        with patch.object(ManagementRoot, '_get_tmos_version'):
            bigip = ManagementRoot(
                '1.2.3.4',
                'admin',
                'default',
                port=443,
                token='tmos')
            self.assertRaises(F5CcclSchemaError, ctlr.K8sCloudServiceManager,
                              bigip,
                              'test',
                              schema_path='not/a/valid/path.json')

        cfg = {"ltm": "not valid json"}
        self.assertRaises(F5CcclValidationError, self.mgr._apply_config, cfg)

        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)

        # Corrupt the config
        del cfg['ltm']['virtualServers'][0]['name']
        self.assertRaises(F5CcclValidationError, self.mgr._apply_config, cfg)

    def test_kubernetes_configs(self):
        """Test: Verify expected BIG-IP config created from Marathon state."""
        # Verify configuration
        for data_file in kubernetes_test_data:
            expected_file = data_file.replace('.json', '_expected.json')
            self.verify_kubernetes_config(data_file, expected_file)

    def test_pool_only_to_virtual_server(
            self,
            cloud_state='tests/kubernetes_one_svc_two_nodes_pool_only.json'):
        """Test: Kubernetes app without virtual server gets virtual server."""
        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)

        # Reconfigure BIG-IP by adding virtual server to existing pool
        self.cloud_data['resources']['virtualServers'][0].update(
            {
                unicode('virtualAddress'):
                {
                    unicode('bindAddr'):
                        unicode('10.128.10.240'),
                    unicode('port'):
                        5051
                }
            })
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)

    def test_virtual_server_to_pool_only(
            self,
            cloud_state='tests/kubernetes_one_svc_two_nodes.json'):
        """Test: Kubernetes app with virtual server removes virtual server."""
        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)

        # Reconfigure BIG-IP by removing virtual server
        self.cloud_data['resources']['virtualServers'][0].pop(
            unicode('virtualAddress'))
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)

    def test_network_0_existing_vxlan_nodes_0_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_0_records.json',
            cloud_state='tests/kubernetes_openshift_0_nodes.json'):
        """Test: openshift environment with 0 nodes."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)

        # Verify we only query bigip once for the initial state and
        # don't try to write an update if nothing has changed.
        self.assertEqual(self.mgr.mgmt_root().
                         tm.net.fdb.tunnels.tunnel.load.call_count, 1)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_1_existing_vxlan_nodes_1_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_1_record.json',
            cloud_state='tests/kubernetes_openshift_1_node.json'):
        """Test: openshift environment with 1 nodes."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)

        # Verify we only query bigip once for the initial state and
        # don't try to write an update if nothing has changed.
        self.assertEqual(self.mgr.mgmt_root().
                         tm.net.fdb.tunnels.tunnel.load.call_count, 1)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_1_existing_vxlan_nodes_0_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_1_record.json',
            cloud_state='tests/kubernetes_openshift_0_nodes.json'):
        """Test: openshift environment with 1 existing node, 0 requested."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.mgr.mgmt_root().
                         tm.net.fdb.tunnels.tunnel.load.call_count, 2)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_0_existing_vxlan_nodes_1_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_0_records.json',
            cloud_state='tests/kubernetes_openshift_1_node.json'):
        """Test: openshift environment with 0 existing nodes, 1 requested."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.mgr.mgmt_root().
                         tm.net.fdb.tunnels.tunnel.load.call_count, 2)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_1_existing_vxlan_nodes_3_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_1_record.json',
            cloud_state='tests/kubernetes_openshift_3_nodes.json'):
        """Test: Kubernetes openshift environment with 0 nodes."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.mgr.mgmt_root().
                         tm.net.fdb.tunnels.tunnel.load.call_count, 2)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_3_existing_vxlan_nodes_1_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_3_records.json',
            cloud_state='tests/kubernetes_openshift_1_node.json'):
        """Test: Kubernetes openshift environment with 0 nodes."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.mgr.mgmt_root().
                         tm.net.fdb.tunnels.tunnel.load.call_count, 2)

        # Compare final content with self.network_state - should be the same
        self.assertEqual(self.compute_fdb_records(), self.vxlan_tunnel.records)

    def test_network_bad_vxlan_ip(
            self,
            network_state='tests/bigip_test_vxlan_3_records.json',
            cloud_state='tests/kubernetes_openshift_1_node.json'):
        """Test: BigIP not updated if IP address in badly formatted."""
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Verify original configuration is untouched if we have errors
        # in the cloud config file
        self.cloud_data['openshift-sdn']['vxlan-node-ips'][0] = '55'
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)
        self.assertEqual(self.network_data, self.vxlan_tunnel.records)

        self.cloud_data['openshift-sdn']['vxlan-node-ips'][0] = 55
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)
        self.assertEqual(self.network_data, self.vxlan_tunnel.records)

        self.cloud_data['openshift-sdn']['vxlan-node-ips'][0] = 'myaddr'
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)
        self.assertEqual(self.network_data, self.vxlan_tunnel.records)

    def test_network_bad_partition_name(
            self,
            network_state='tests/bigip_test_vxlan_3_records.json',
            cloud_state='tests/kubernetes_openshift_1_node.json'):
        """Test: BigIP not updated if the partition name format is bad."""
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Verify original configuration is untouched if we have errors
        # in the cloud config file
        self.cloud_data['openshift-sdn']['vxlan-name'] = \
            '/bad/partition/name/idf/'
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)
        self.assertFalse(hasattr(self, 'vxlan_tunnel'))

        self.cloud_data['openshift-sdn']['vxlan-name'] = \
            'bad/partition/name'
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)
        self.assertFalse(hasattr(self, 'vxlan_tunnel'))

        self.cloud_data['openshift-sdn']['vxlan-name'] = ''
        cfg = ctlr.create_config_kubernetes(self.mgr.get_partition(),
                                            self.cloud_data)
        self.mgr._apply_config(cfg)
        self.assertFalse(hasattr(self, 'vxlan_tunnel'))

    def compute_fdb_records(self):
        """Create a FDB record for each openshift node."""
        records = []
        if self.cloud_data and 'openshift-sdn' in self.cloud_data and \
                'vxlan-node-ips' in self.cloud_data['openshift-sdn']:
            for node_ip in self.cloud_data['openshift-sdn']['vxlan-node-ips']:
                record = {'endpoint': node_ip, 'name': ipv4_to_mac(node_ip)}
                records.append(record)
        return records


if __name__ == '__main__':
    unittest.main()
