"""
Create a mock driver and attempt to call each mock method that RTwo adds data
to!
"""

import unittest
from mock import Mock, patch

from rtwo.test.secrets import OPENSTACK_PARAMS

from libcloud.utils.py3 import httplib
from libcloud.utils.py3 import method_type
from libcloud.utils.py3 import u
from libcloud.common.types import LibcloudError
from libcloud.compute.types import Provider, KeyPairDoesNotExistError

from libcloud.compute.providers import get_driver
from libcloud.compute.drivers.openstack import (
    OpenStackSecurityGroup, OpenStackSecurityGroupRule,
    OpenStack_1_1_FloatingIpPool, OpenStack_1_1_FloatingIpAddress,
    OpenStackKeyPair
)
from libcloud.test.compute.test_openstack import OpenStack_1_1_MockHttp, \
                                                 OpenStackMockHttp
from libcloud.test.compute.test_openstack import OpenStack_1_1_Tests
from rtwo.drivers.openstack_facade import OpenStack_Esh_Connection,OpenStack_Esh_NodeDriver

######

class OpenStackEshConnectionTest(unittest.TestCase):
    def setUp(self):
        self.timeout = 10
        OpenStack_Esh_Connection.conn_classes = (None, Mock())
        self.connection = OpenStack_Esh_Connection('foo', 'bar',
                                                  timeout=self.timeout,
                                                  ex_force_auth_url='https://127.0.0.1')
        self.connection.driver = Mock()
        self.connection.driver.name = 'OpenStackEshDriver'

    def test_timeout(self):
        self.connection.connect()
        self.assertEqual(self.connection.timeout, self.timeout)
        self.connection.conn_classes[1].assert_called_with(host='127.0.0.1',
                                                           port=443,
                                                           timeout=10)

class OpenStackEshDriverTest(OpenStack_1_1_Tests):
    driver_args = OPENSTACK_PARAMS
    driver_klass = OpenStack_Esh_NodeDriver
    driver_type = OpenStack_Esh_NodeDriver

    def setUp(self):
        super(OpenStackEshDriverTest, self).setUp()


