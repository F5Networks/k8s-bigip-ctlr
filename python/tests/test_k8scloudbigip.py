# Copyright 2018 F5 Networks
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

Units tests for testing BIG-IP resource management.

"""
from __future__ import absolute_import

import unittest
import json
from mock import Mock, mock_open, patch
from f5_cccl.utils.mgmt import ManagementRoot
from f5_cccl.bigip import BigIPProxy
from f5_cccl.utils.mgmt import mgmt_root
from f5_cccl.exceptions import F5CcclValidationError
from .. import bigipconfigdriver as ctlr


# Cloud app data
cloud_test_data = [
    'tests/kubernetes_one_svc_two_nodes.json',
    'tests/kubernetes_one_udp_svc_two_nodes.json',
    'tests/kubernetes_invalid_svcs.json',
    'tests/kubernetes_one_svc_one_node.json',
    'tests/kubernetes_one_svc_four_nodes.json',
    'tests/kubernetes_one_iapp.json',
    'tests/kubernetes_no_apps.json',
]


class CloudTest(unittest.TestCase):
    """Cloud/Big-IP configuration tests.

    Test BIG-IP configuration given various cloud states and existing
    BIG-IP states
    """

    def setUp(self):
        """Test suite set up."""
        # Mock the call to _get_tmos_version(), which tries to make a
        # connection
        partition = 'k8s'
        with patch.object(ManagementRoot, '_get_tmos_version'):
            bigip = mgmt_root('1.2.3.4', 'admin', 'default', 443, 'tmos')

            self.mgr = ctlr.CloudServiceManager(
                bigip,
                partition)

        self.bigip = bigip
        self.cccl = self.mgr._cccl
        self.cccl._service_manager._service_deployer._bigip.refresh_ltm = \
            Mock()
        self.cccl._service_manager._service_deployer.deploy_ltm = \
            Mock(return_value=0)

    def read_test_vectors(self, cloud_state, network_state=None):
        """Read test vectors for the various states."""
        # Read the cloud state
        if cloud_state:
            with open(cloud_state) as json_data:
                self.cloud_data = json.load(json_data)

        if network_state:
            with open(network_state) as json_data:
                self.network_data = json.load(json_data)

    def verify_cloud_config(self, cloud_state, expected_state):
        """Test: Verify expected config created from the cloud state."""
        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_ltm_config(self.mgr.get_partition(), self.cloud_data)

        with open(expected_state) as json_data:
                exp = json.load(json_data)
        self.assertEqual(cfg, exp['ltm'])

        with patch.object(BigIPProxy, 'get_default_route_domain') as \
                mock_bigip_gdrd:
            mock_bigip_gdrd.return_value = 0
            self.mgr._apply_ltm_config(cfg)

    def test_cccl_exceptions(
            self,
            cloud_state='tests/kubernetes_one_svc_two_nodes.json'):
        """Test: CCCL exceptions."""
        cfg = {"not valid json"}
        self.assertRaises(F5CcclValidationError, self.mgr._apply_ltm_config,
                          cfg)

        # Get the test data
        self.read_test_vectors(cloud_state)

        # Do the BIG-IP configuration
        cfg = ctlr.create_ltm_config(self.mgr.get_partition(), self.cloud_data)

        # Corrupt the config
        del cfg['virtualServers'][0]['name']
        self.assertRaises(F5CcclValidationError, self.mgr._apply_ltm_config,
                          cfg)

    def test_cloud_configs(self):
        """Test: Verify expected BIG-IP config created from cloud state."""
        # Verify configuration
        for data_file in cloud_test_data:
            expected_file = data_file.replace('.json', '_expected.json')
            self.verify_cloud_config(data_file, expected_file)

    def test_user_agent(self):
        """Test: Setting ICR session user-agent from build info."""
        # Invalid build info
        with patch('__builtin__.open',
                   mock_open(read_data="This is not valid build info")):
            assert 'k8s-bigip-ctlr-VERSION-UNKNOWN' == ctlr._set_user_agent()

        # Valid build info
        version_info = '{\"version\":\"1.3.0\",\"build\":\"abcdef0123456\"}'
        with patch('__builtin__.open', mock_open(read_data=version_info)):
            assert 'k8s-bigip-ctlr-1.3.0-abcdef0123456' == \
                ctlr._set_user_agent()


if __name__ == '__main__':
    unittest.main()
