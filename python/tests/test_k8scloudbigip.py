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
import unittest
from mock import Mock, patch
from f5_cccl.common import ipv4_to_mac
from f5.bigip import BigIP
from f5_cccl.testcommon import BigIPTest, MockIapp
ctlr = __import__('bigipconfigdriver')


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


class KubernetesTest(BigIPTest):
    """Kubernetes/Big-IP configuration tests.

    Test BIG-IP configuration given various Kubernetes states and existing
    BIG-IP states
    """

    def setUp(self):
        """Test suite set up."""
        # Mock the call to _get_tmos_version(), which tries to make a
        # connection
        partition = 'k8s'
        with patch.object(BigIP, '_get_tmos_version'):
            bigip = ctlr.K8sCloudBigIP('1.2.3.4', '443', 'admin',
                                       'default', [partition], manage_types=[
                                           '/tm/ltm/virtual',
                                           '/tm/ltm/pool',
                                           '/tm/ltm/monitor',
                                           '/tm/sys/application/service'])
        super(KubernetesTest, self).setUp(partition, bigip)

        self.bigip.fdb_records_update_orig = self.bigip.fdb_records_update
        self.bigip.get_fdb_records_orig = self.bigip.get_fdb_records

        # mock out the bigip.net.fdb.tunnels.tunnel resource
        self.bigip.net = type('', (), {})()
        self.bigip.net.fdb = type('', (), {})()
        self.bigip.net.fdb.tunnels = type('', (), {})()
        self.bigip.net.fdb.tunnels.tunnel = type('', (), {})()
        self.bigip.net.fdb.tunnels.tunnel.load = \
            Mock(side_effect=self.mock_net_fdb_tunnels_tunnel_load)

    def mock_net_fdb_tunnels_tunnel_load(self, partition, name):
        """Mock: Get a mocked vxla tunnel to store the vxlan record config."""
        if not hasattr(self, 'vxlan_tunnel'):
            # create a BigIP resource to store the 'current' tunnel
            # FDB as well as updates.
            self.vxlan_tunnel = VxLANTunnel(partition, name, self.network_data)
        return self.vxlan_tunnel

    def test_svc_create(self,
                        cloud_state='tests/kubernetes_one_svc_two_nodes.json',
                        bigip_state='tests/bigip_test_blank.json',
                        hm_state='tests/bigip_test_blank.json'):
        """Test: Kubernetes service created."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.member_create.called)
        self.assertEqual(self.bigip.member_create.call_count, 2)

        self.assertEquals(2, len(self.test_monitor))
        expected_names = ['default_configmap', 'default_configmap_1']
        for mon in self.test_monitor:
            self.assertTrue(mon['name'] in expected_names)
            self.assertEqual(self.test_partition, mon['partition'])

    def test_invalid_svcs(self,
                          cloud_state='tests/kubernetes_invalid_svcs.json',
                          bigip_state='tests/bigip_test_blank.json',
                          hm_state='tests/bigip_test_blank.json'):
        """Test: Kubernetes invalid services are not created."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.member_create.called)
        self.assertEqual(self.bigip.member_create.call_count, 2)

        self.assertEquals(2, len(self.test_virtual))
        self.assertEquals(2, len(self.test_pool))

        expected_names = ['invalid_sslProfile0_configmap',
                          'invalid_sslProfile1_configmap']
        for v in self.test_virtual:
            self.assertTrue(v['name'] in expected_names)
            self.assertEquals(self.test_partition, v['partition'])
        for p in self.test_pool:
            self.assertTrue(p['name'] in expected_names)
            self.assertEquals(self.test_partition, p['partition'])

    def test_svc_scaled_down(
            self,
            cloud_state='tests/kubernetes_one_svc_one_node.json',
            bigip_state='tests/bigip_test_one_svc_two_nodes.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Kubernetes service scaled down."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.member_delete.called)
        self.assertEqual(self.bigip.member_delete.call_count, 1)

    def test_svc_scaled_up(
            self,
            cloud_state='tests/kubernetes_one_svc_four_nodes.json',
            bigip_state='tests/bigip_test_one_svc_two_nodes.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Kubernetes service scaled up."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP configuration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertTrue(self.bigip.member_update.called)
        self.assertTrue(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertTrue(self.bigip.member_create.called)
        self.assertEqual(self.bigip.member_create.call_count, 2)

    def test_new_iapp(self, cloud_state='tests/kubernetes_one_iapp.json',
                      bigip_state='tests/bigip_test_blank.json',
                      hm_state='tests/bigip_test_blank.json'):
        """Test: Start Kubernetes app with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        self.bigip.iapp_create = self.bigip.iapp_create_orig
        self.bigip.sys.application.services.service.create = \
            Mock(side_effect=self.mock_iapp_service_create)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)

        expected_name = 'default_configmap'

        # Verfiy the iapp variables and tables
        expected_tables = \
            [{'columnNames': ['addr', 'port', 'connection_limit'], 'rows':
             [{'row': [u'172.16.0.5', u'30008', '0']}],
             'name': u'pool__members'}]
        expected_variables = \
            [{'name': u'monitor__monitor', 'value': u'/#create_new#'},
             {'name': u'net__client_mode', 'value': u'wan'},
             {'name': u'pool__pool_to_use', 'value': u'/#create_new#'},
             {'name': u'net__server_mode', 'value': u'lan'},
             {'name': u'pool__addr', 'value': u'10.128.10.240'},
             {'name': u'monitor__response', 'value': u'none'},
             {'name': u'monitor__uri', 'value': u'/'},
             {'name': u'pool__port', 'value': u'8080'}]

        self.assertEquals(expected_name, self.test_iapp.name)
        self.assertEquals(expected_tables, self.test_iapp.tables)
        self.assertEquals(expected_variables, self.test_iapp.variables)

    def test_update_iapp(self, cloud_state='tests/kubernetes_one_iapp.json',
                         bigip_state='tests/kubernetes_one_iapp.json',
                         hm_state='tests/bigip_test_blank.json'):
        """Test: Update Kubernetes app with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        self.bigip.sys.application.services.get_collection = \
            Mock(side_effect=self.mock_iapp_update_services_get_collection)
        self.bigip.sys.application.services.service.load = \
            Mock(side_effect=self.mock_iapp_update_service_load)
        self.bigip.iapp_update = self.bigip.iapp_update_orig
        self.bigip.cleanup_nodes = Mock()

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)

        iapp_def = self.bigip.iapp_build_definition(
            cfg['ltm']['virtualServers']['default_configmap'])
        self.test_iapp = MockIapp(name='default_configmap',
                                  partition=self.test_partition,
                                  variables=iapp_def['variables'],
                                  tables=iapp_def['tables'])

        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)

        expected_name = 'default_configmap'
        self.assertEquals(expected_name, self.test_iapp_list[0].name)

    def test_delete_iapp(self, cloud_state='tests/kubernetes_no_apps.json',
                         bigip_state='tests/bigip_test_blank.json',
                         hm_state='tests/bigip_test_blank.json'):
        """Test: Delete Kubernetes app associated with iApp."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        self.bigip.iapp_delete = self.bigip.iapp_delete_orig
        self.bigip.sys.application.services.get_collection = \
            Mock(side_effect=self.mock_iapp_services_get_collection)
        self.bigip.sys.application.services.service.load = \
            Mock(side_effect=self.mock_iapp_service_load)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.load.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertFalse(self.bigip.member_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertFalse(self.bigip.ltm.monitor.https.http.create.called)
        self.assertFalse(self.bigip.iapp_create.called)

        expected_name = 'server-app2_iapp_10000_vs'
        self.assertEqual(len(self.test_iapp_list), 1)
        self.assertEqual(self.test_iapp_list[0].partition,
                         self.test_partition)
        self.assertEqual(self.test_iapp_list[0].name, expected_name)
        self.assertEqual(self.test_iapp.partition, self.test_partition)
        self.assertEqual(self.test_iapp.name, expected_name)

    def test_updates(self,
                     cloud_state='tests/kubernetes_one_svc_two_nodes.json',
                     bigip_state='tests/bigip_test_one_svc_two_nodes.json',
                     hm_state='tests/bigip_test_blank.json'):
        """Test: Verify BIG-IP updates.

        Verify that resources are only updated when the state
        of the resource changes.
        """
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Restore the mocked 'update' functions to their original state
        self.bigip.pool_update = self.bigip.pool_update_orig
        self.bigip.virtual_update = self.bigip.virtual_update_orig
        self.bigip.member_update = self.bigip.member_update_orig

        # Mock the 'get' resource functions. We will use these to supply
        # mocked resources
        self.bigip.get_pool = Mock(side_effect=self.mock_get_pool)
        self.bigip.get_virtual = Mock(side_effect=self.mock_get_virtual)
        self.bigip.get_virtual_profiles = Mock(
            side_effect=self.mock_get_virtual_profiles)
        self.bigip.get_member = Mock(side_effect=self.mock_get_member)
        self.bigip.get_virtual_address = Mock(
            side_effect=self.mock_get_virtual_address)

        # Create a mock Pool
        pool_data_unchanged = {'monitor': '/k8s/default_configmap and '
                                          '/k8s/default_configmap_1',
                               'balance': 'round-robin'}
        pool = self.create_mock_pool('default_configmap',
                                     **pool_data_unchanged)

        # Create a mock Virtual
        virtual_data_unchanged = {'enabled': True,
                                  'disabled': False,
                                  'ipProtocol': 'tcp',
                                  'destination': '/k8s/10.128.10.240:5051',
                                  'pool': '/k8s/default_configmap',
                                  'sourceAddressTranslation':
                                  {'type': 'automap'},
                                  'profiles': [{'partition': 'Common',
                                                'name': 'clientssl'},
                                               {'partition': 'Common',
                                                'name': 'clientssl-secure'},
                                               {'partition': 'Common',
                                                'name': 'http'}]}
        virtual = self.create_mock_virtual('default_configmap',
                                           **virtual_data_unchanged)

        # Create mock Pool Members
        member_data_unchanged = {'state': 'user-up', 'session': 'user-enabled'}
        member = self.create_mock_pool_member('172.16.0.5:30008',
                                              **member_data_unchanged)
        member = self.create_mock_pool_member('172.16.0.6:30008',
                                              **member_data_unchanged)

        # Pool, Virtual, and Member are not modified
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)
        self.assertFalse(pool.modify.called)
        self.assertFalse(virtual.modify.called)
        self.assertFalse(virtual.profiles_s.profiles.create.called)
        self.assertFalse(member.modify.called)

        # Pool is modified
        pool_data_changed = {
            'balance': 'least-connections'
        }
        for key in pool_data_changed:
            data = pool_data_unchanged.copy()
            # Change one thing
            data[key] = pool_data_changed[key]
            pool = self.create_mock_pool('default_configmap', **data)
            cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(pool.modify.called)

        # Virtual is modified
        virtual_data_changed = {
            'enabled': False,
            'disabled': True,
            'ipProtocol': 'udp',
            'destination': '/Common/10.128.10.240:5051',
            'pool': '/Common/default_configmap',
            'sourceAddressTranslation': {'type': 'snat'},
            'profiles': [{'partition': 'Common', 'name': 'clientssl'},
                         {'partition': 'Common', 'name': 'clientssl-secure'},
                         {'partition': 'Common', 'name': 'tcp'}]
        }
        for key in virtual_data_changed:
            data = virtual_data_unchanged.copy()
            # Change one thing
            data[key] = virtual_data_changed[key]
            virtual = self.create_mock_virtual('default_configmap',
                                               **data)
            cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(virtual.modify.called)

        # Member is modified
        member_data_changed = {
            'state': 'user-down',
            'session': 'user-disabled'
        }
        for key in member_data_changed:
            data = member_data_unchanged.copy()
            # Change one thing
            data[key] = member_data_changed[key]
            member = self.create_mock_pool_member('172.16.0.5:30008',
                                                  **data)
            cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(member.modify.called)

        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)

    def test_create_pool_only(
            self,
            cloud_state='tests/kubernetes_one_svc_two_nodes_pool_only.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Marathon app that does not create a virtual server."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP configuration
        self.assertFalse(self.bigip.pool_update.called)
        self.assertFalse(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertTrue(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertEqual(self.bigip.ltm.virtuals.virtual.create.call_count, 0)
        self.assertEqual(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.https.http.create.call_count,
                         1)

        expected_pool_name = 'default_configmap'
        expected_names = ['default_configmap', 'default_configmap_1']
        self.assertEqual(1, len(self.test_pool))
        self.assertEqual(0, len(self.test_virtual))
        self.assertEqual(2, len(self.test_monitor))
        self.assertEqual(expected_pool_name, self.test_pool[0]['name'])
        self.assertEqual(self.test_partition, self.test_pool[0]['partition'])
        for mon in self.test_monitor:
            self.assertTrue(mon['name'] in expected_names)
            self.assertEqual(self.test_partition, mon['partition'])

    def test_pool_only_to_virtual_server(
            self,
            cloud_state='tests/kubernetes_one_svc_two_nodes_pool_only.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Marathon app without a virtual server gets virtual server."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Mock out functions not directly under test
        self.bigip.get_pool_list = Mock(side_effect=self.mock_get_pool_list)
        self.bigip.get_virtual_list = \
            Mock(side_effect=self.mock_get_virtual_list)
        self.bigip.get_healthcheck_list = \
            Mock(side_effect=self.mock_get_healthcheck_list)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP initial configuration
        self.assertEqual(self.bigip.ltm.virtuals.virtual.create.call_count, 0)
        self.assertEqual(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.https.http.create.call_count,
                         1)

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
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP reconfiguration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertTrue(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertEqual(self.bigip.ltm.virtuals.virtual.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.https.http.create.call_count,
                         1)

        expected_virtual_name = 'default_configmap'
        expected_pool_name = 'default_configmap'
        expected_names = ['default_configmap', 'default_configmap_1']
        self.assertEqual(1, len(self.test_pool))
        self.assertEqual(1, len(self.test_virtual))
        self.assertEqual(2, len(self.test_monitor))
        self.assertEqual(expected_pool_name, self.test_pool[0]['name'])
        self.assertEqual(expected_virtual_name, self.test_virtual[0]['name'])
        self.assertEqual(self.test_partition, self.test_pool[0]['partition'])
        for mon in self.test_monitor:
            self.assertTrue(mon['name'] in expected_names)
            self.assertEqual(self.test_partition, mon['partition'])

    def test_virtual_server_to_pool_only(
            self,
            cloud_state='tests/kubernetes_one_svc_two_nodes.json',
            bigip_state='tests/bigip_test_blank.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Marathon app with virtual server removes virtual server."""
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Mock out functions not directly under test
        self.bigip.get_pool_list = Mock(side_effect=self.mock_get_pool_list)
        self.bigip.get_virtual_list = \
            Mock(side_effect=self.mock_get_virtual_list)
        self.bigip.get_healthcheck_list = \
            Mock(side_effect=self.mock_get_healthcheck_list)
        self.bigip.virtual_delete = Mock(side_effect=self.mock_virtual_delete)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP initial configuration
        self.assertEqual(self.bigip.ltm.virtuals.virtual.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.https.http.create.call_count,
                         1)

        # Reconfigure BIG-IP by adding virtual server to existing pool
        self.cloud_data['resources']['virtualServers'][0].pop(
            unicode('virtualAddress'))
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify BIG-IP reconfiguration
        self.assertTrue(self.bigip.pool_update.called)
        self.assertTrue(self.bigip.healthcheck_update.called)
        self.assertFalse(self.bigip.member_update.called)
        self.assertFalse(self.bigip.virtual_update.called)
        self.assertFalse(self.bigip.iapp_update.called)

        self.assertTrue(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertTrue(self.bigip.ltm.pools.pool.create.called)
        self.assertTrue(self.bigip.ltm.monitor.tcps.tcp.create.called)
        self.assertTrue(self.bigip.ltm.monitor.https.http.create.called)
        self.assertTrue(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)
        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)

        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.ltm.monitor.tcps.tcp.load.called)
        self.assertEqual(self.bigip.ltm.virtuals.virtual.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.pools.pool.create.call_count, 1)
        self.assertEqual(self.bigip.ltm.monitor.https.http.create.call_count,
                         1)

        self.assertEqual(1, len(self.test_pool))
        self.assertEqual(0, len(self.test_virtual))
        self.assertEqual(2, len(self.test_monitor))
        expected_names = ['default_configmap', 'default_configmap_1']
        expected_pool_name = 'default_configmap'
        self.assertEqual(expected_pool_name, self.test_pool[0]['name'])
        self.assertEqual(self.test_partition, self.test_pool[0]['partition'])
        for mon in self.test_monitor:
            self.assertTrue(mon['name'] in expected_names)
            self.assertEqual(self.test_partition, mon['partition'])

    def test_updates_pool_only(
            self,
            cloud_state='tests/kubernetes_one_svc_two_nodes_pool_only.json',
            bigip_state='tests/bigip_test_one_svc_two_nodes.json',
            hm_state='tests/bigip_test_blank.json'):
        """Test: Verify BIG-IP updates in pool only mode.

        Verify that resources are only updated when the state
        of the resource changes.
        """
        # Get the test data
        self.read_test_vectors(cloud_state, bigip_state, hm_state)

        # Restore the mocked 'update' functions to their original state
        self.bigip.pool_update = self.bigip.pool_update_orig
        self.bigip.member_update = self.bigip.member_update_orig
        self.bigip.healthcheck_update = self.bigip.healthcheck_update_orig

        # Mock the 'get' resource functions. We will use these to supply
        # mocked resources
        self.bigip.get_pool = Mock(side_effect=self.mock_get_pool)
        self.bigip.get_virtual = Mock(side_effect=self.mock_get_virtual)
        self.bigip.get_member = Mock(side_effect=self.mock_get_member)
        self.bigip.get_healthcheck = Mock(
            side_effect=self.mock_get_healthcheck)

        # Create a mock Pool
        pool_data_unchanged = {'monitor': '/k8s/default_configmap and '
                                          '/k8s/default_configmap_1',
                               'balance': 'round-robin'}
        pool = self.create_mock_pool('default_configmap',
                                     **pool_data_unchanged)

        # Create mock Pool Members
        member_data_unchanged = {'state': 'user-up', 'session': 'user-enabled'}
        member = self.create_mock_pool_member('172.16.0.5:30008',
                                              **member_data_unchanged)
        member = self.create_mock_pool_member('172.16.0.6:30008',
                                              **member_data_unchanged)

        # Pool, Member, and Healthcheck are not modified
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)
        self.assertFalse(pool.modify.called)
        self.assertFalse(member.modify.called)

        # Pool is modified
        pool_data_changed = {
            'balance': 'least-connections'
        }
        for key in pool_data_changed:
            data = pool_data_unchanged.copy()
            # Change one thing
            data[key] = pool_data_changed[key]
            pool = self.create_mock_pool('default_configmap', **data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(pool.modify.called)

        # Member is modified
        member_data_changed = {
            'state': 'user-down',
            'session': 'user-disabled'
        }
        for key in member_data_changed:
            data = member_data_unchanged.copy()
            # Change one thing
            data[key] = member_data_changed[key]
            member = self.create_mock_pool_member('172.16.0.5:30008',
                                                  **data)
            self.bigip.regenerate_config_f5(cfg)
            self.assertTrue(member.modify.called)

        self.assertFalse(self.bigip.iapp_create.called)
        self.assertFalse(self.bigip.iapp_delete.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.create.called)
        self.assertFalse(self.bigip.ltm.virtuals.virtual.load.called)
        self.assertFalse(self.bigip.ltm.pools.pool.create.called)
        self.assertFalse(self.bigip.ltm.pools.get_collection.called)
        self.assertFalse(self.bigip.member_create.called)
        self.assertFalse(self.bigip.member_delete.called)

    def test_network_0_existing_vxlan_nodes_0_requested_vxlan_nodes(
            self,
            network_state='tests/bigip_test_vxlan_0_records.json',
            cloud_state='tests/kubernetes_openshift_0_nodes.json'):
        """Test: openshift environment with 0 nodes."""
        # Get the test data
        self.read_test_vectors(cloud_state=cloud_state,
                               network_state=network_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify we only query bigip once for the initial state and
        # don't try to write an update if nothing has changed.
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 1)

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
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify we only query bigip once for the initial state and
        # don't try to write an update if nothing has changed.
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 1)

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
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 2)

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
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 2)

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
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 2)

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
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)

        # Verify we first query bigip once for the initial state and
        # then perform an update due to differences
        self.assertEqual(self.bigip.net.fdb.tunnels.tunnel.load.call_count, 2)

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
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)
        self.assertEqual(self.network_data, self.vxlan_tunnel.records)

        self.cloud_data['openshift-sdn']['vxlan-node-ips'][0] = 55
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)
        self.assertEqual(self.network_data, self.vxlan_tunnel.records)

        self.cloud_data['openshift-sdn']['vxlan-node-ips'][0] = 'myaddr'
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)
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
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)
        self.assertFalse(hasattr(self, 'vxlan_tunnel'))

        self.cloud_data['openshift-sdn']['vxlan-name'] = \
            'bad/partition/name'
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)
        self.assertFalse(hasattr(self, 'vxlan_tunnel'))

        self.cloud_data['openshift-sdn']['vxlan-name'] = ''
        cfg = ctlr.create_config_kubernetes(self.bigip, self.cloud_data)
        self.bigip.regenerate_config_f5(cfg)
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
