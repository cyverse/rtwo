"""
Extension of libcloud's OpenStack Node Driver.
"""
import binascii
import copy
import random
import json
import os
import socket
import sys
import time
from datetime import datetime

from threepio import logger

import libcloud.compute.ssh

from libcloud.compute.types import Provider, NodeState, DeploymentError,\
    LibcloudError
from libcloud.compute.base import StorageVolume, VolumeSnapshot,\
    NODE_ONLINE_WAIT_TIMEOUT, SSH_CONNECT_TIMEOUT,\
    NodeAuthPassword, NodeDriver
from libcloud.compute.deployment import MultiStepDeployment, ScriptDeployment
from libcloud.compute.drivers.openstack import \
        OpenStack_1_1_NodeDriver,\
        OpenStack_1_1_Connection
from libcloud.utils.py3 import httplib
try:
    from lxml import etree as ET
except ImportError:
    from xml.etree import ElementTree as ET

from neutronclient.common.exceptions import NeutronClientException
from requests.exceptions import BaseHTTPError

from rfive.fabricSSH import FabricSSHClient

from rtwo.exceptions import NonZeroDeploymentException, ConnectionFailure
from rtwo.drivers.openstack_network import NetworkManager
from rtwo.drivers.openstack_user import UserManager
import functools

def swap_service_catalog(service_type=None, name=None):
    """
    Use this temporary decorator to take advantage of the full service catalog
    offered by OpenStack.
    TODO:Remove this when JMatts decorator is merged in!
    """
    def decorator(method):
        def service_catalog_switch(*args, **kwargs):
            """
            Switch service_catalog endpoints, then switch back!
            """
            driver = args[0]
            lc_conn = driver.connection
            if not lc_conn.service_catalog:
                lc_conn.get_service_catalog() # Make a request.
            if lc_conn._ex_force_base_url:
                old_endpoint = lc_conn._ex_force_base_url
            else:
                old_endpoint = lc_conn.get_endpoint()
            try:
                new_service = lc_conn.service_catalog.get_endpoint(
                    service_type=service_type, name=name,
                    region=lc_conn.service_region)
                if getattr(new_service, "url"):
                    lc_conn._ex_force_base_url = new_service.url
                else:
                    lc_conn._ex_force_base_url = new_service["url"]
                return method(*args, **kwargs)
            finally:
                lc_conn._ex_force_base_url = old_endpoint
        return service_catalog_switch
    return decorator

class OpenStack_Esh_Connection(OpenStack_1_1_Connection):
    #Ripped from OpenStackBaseConnection.__init__()
    def __init__(self, *args, **kwargs):
        timeout = kwargs.pop('timeout',None)
        #NOTE: If 'max attempts' is logic available in libcloud, Remove this and the 'request' logic, in favor of:
        # RETRY_FAILED_HTTP_REQUESTS: https://github.com/apache/libcloud/blob/trunk/libcloud/common/base.py#L76-L77
        # Be sure to set `retry_delay` and `backoff` in addition to `timeout`..
        self.max_attempts = kwargs.pop('max_attempts',2)
        if not timeout:
            timeout = 20 # Default 20 Second timeouts
        super(OpenStack_Esh_Connection, self).__init__(
            *args, timeout=timeout, **kwargs)

    def request(self, action, params=None,
                data='', headers=None, method='GET', max_attempts=None):
        if not max_attempts:
            max_attempts = self.max_attempts
        current_attempt = 0
        while current_attempt < max_attempts:
            try:
                current_attempt += 1
                response = super(OpenStack_1_1_Connection, self).request(
                        action=action,
                        params=params, data=data,
                        method=method, headers=headers)
                return response
            except (BaseHTTPError, httplib.HTTPException, socket.error,
                    socket.gaierror, httplib.BadStatusLine), e:
                _hostname = "%s:%s" % (self.host,self.port)
                logger.error("Request %s %s%s failed with error: %s - %s. Retry #%s/%s"
                        % (method, _hostname, action, e.__class__.__name__, e.args,
                           current_attempt, max_attempts))
                if current_attempt >= max_attempts:
                    logger.error("Final attempt failed! Request diagnostics:"
                            "URL:%s/%s, params=%s, data=%s,"
                            "method=%s, headers=%s"
                            % (_hostname, action, params, data, method, headers))
                    #This 3-tuple will re-raise the exception.
                    raise ConnectionFailure,\
                          "Final connection attempt exhausted:"\
                          " %s - %s" % (_hostname, e),\
                          sys.exc_info()[2]
                #DON'T FORGET TO WAIT BEFORE YOU RETRY! (4sec, 8sec)
                sleep_time = random.randint(0,2 ** current_attempt)
                time.sleep(sleep_time)
                logger.error("Waited %s seconds. Attempting again." % sleep_time)
            except Exception, e:
                raise

class OpenStack_Esh_NodeDriver(OpenStack_1_1_NodeDriver):
    """
    OpenStack node driver for esh.
    """
    connectionCls = OpenStack_Esh_Connection

    features = {
        "_to_volume": ["Convert native object to StorageVolume"],
        "_to_size": ["Add cpu info to extra, duplicate of vcpu"],
        "_to_image": ["Add state info to extra"],
        "_to_node": ["Build public_ips field",
                     "public_ips as extra",
                     "keypairs as extra",
                     "user/tenant as extra"],
        "create_node": ["Create node with ssh_key", "ssh_key",
                        "availability_zone"],
        "ex_create_node_with_network": ["Create node with floating IP"
                                        " and ssh_key", "ssh_key"],
        "ex_deploy_to_node": ["Deploy to existing node"],
        "ex_suspend_node": ["Suspends the node"],
        "ex_resume_node": ["Resume the node"],
        "ex_start_node": ["Starts the node"],
        "ex_stop_node": ["Stops the node"],
        "ex_vnc_console": ["Return a novnc token and url for a node."],
        "create_volume": ["Create volume"],
        "list_volumes": ["List all volumes"],
        "ex_list_floating_ip_pools": ["List all floating IP Pools"],
        "ex_delete_ports": ["Delete all ports associated with a node"],
        "ex_allocate_floating_ip": ["Allocate floating IP"],
        "ex_deallocate_floating_ip": ["Deallocate floating IP"],
        "ex_associate_floating_ip": ["Associate floating IP with node"],
        "ex_disassociate_floating_ip": ["Disassociate floating IP from node"],
        "ex_list_all_volumes": ["List all volumes for all tenants"
                                " for the user"],
        "ex_list_volume_attachments": ["List all attached volumes for node"],
        "ex_get_volume_attachment": ["Get details about an attached volume"],
        "ex_create_security_group": ["Add security group to tenant"],
        "ex_delete_security_group": ["Delete security group from tenant"],
        "ex_list_security_groups": ["List all security groups for tenant"],
        "ex_add_security_group": ["Add security group to tenant"],
        "ex_remove_security_group": ["Remove security group from tenant"],
        "ex_create_security_group_rule": ["Add rule to a group"],
        "ex_delete_security_group_rule": ["Remove rule from a group"],
        "ex_list_security_group_rules": ["List all rules for a group"],
        "ex_get_limits": ["Get Rate and Absolute API limits"],
        "ex_os_services": ["Manage services (os-services)"]
    }

    """
    Object builders -- Convert the native dict in to a Libcloud object
    """
    def _to_snapshot(self, api_ss):
        if 'snapshot' in api_ss:
            api_ss = api_ss['snapshot']

        extra = {'volume_id': api_ss.get('volumeId',api_ss.get('volume_id')),
                 'name': api_ss.get('displayName',api_ss.get('display_name')),
                 'created': api_ss.get('createdAt',api_ss.get('created_at')),
                 'description': api_ss.get('displayDescription', api_ss.get('display_description')),
                 'status': api_ss['status']}
        snapshot = VolumeSnapshot(id=api_ss['id'], driver=self,
                                  size=api_ss['size'], extra=extra)
        return snapshot

    def _to_volumes(self, el, cinder=False):
        return [self._to_volume(volume, cinder=cinder)
                for volume in el['volumes']]

    def _cinder_volume_args(self, api_volume):
        api_volume['createdAt'] = api_volume.pop('created_at')
        api_volume['displayName']  = api_volume.pop('name', api_volume.pop('display_name','<No Name>'))
        api_volume['displayDescription'] = api_volume.pop('description', api_volume.pop('display_description',''))
        api_volume['availabilityZone'] = api_volume.pop('availability_zone')
        api_volume['snapshotId'] = api_volume.pop('snapshot_id')
        attachmentSet = api_volume['attachments']
        for attachment in attachmentSet:
            attachment['serverId'] = attachment.pop('server_id')
            attachment['volumeId'] = attachment.pop('volume_id')
        api_volume['attachments'] = attachmentSet
        return api_volume

    def _to_volume(self, api_volume, cinder=False):
        #Unwrap the object, if it wasn't unwrapped already.
        if not api_volume:
            return None
        if 'volume' in api_volume:
            api_volume = api_volume['volume']
        if cinder:
            api_volume = self._cinder_volume_args(api_volume)
        volume = super(OpenStack_Esh_NodeDriver, self)._to_volume(api_volume)

        created_time = datetime.strptime(api_volume['createdAt'], '%Y-%m-%dT%H:%M:%S.%f')
        volume.extra.update({
            'id': api_volume['id'],
            'object': api_volume,
            'displayName': api_volume['displayName'],
            'size': api_volume['size'],
            'status': api_volume['status'],
            'metadata': api_volume['metadata'],
            'availabilityZone': api_volume['availabilityZone'],
            'snapshotId': api_volume['snapshotId'],
            'createTime': created_time,
        })
        return volume

    def _to_size(self, api_size):
        """
        Extends Openstack_1_1_NodeDriver._to_size,
        adds support for cpu
        """
        size = super(OpenStack_Esh_NodeDriver, self)._to_size(api_size)
        size._api = api_size
        size.extra = {
            'cpu': api_size['vcpus'],
            'ephemeral': api_size.get('OS-FLV-EXT-DATA:ephemeral', 0),
            'public': api_size.get('os-flavor-access:is_public', True)
        }
        return size

    def _to_image(self, api_machine):
        """
        Extends Openstack_1_1_NodeDriver._to_image,
        adds support for architecture and state
        """
        #logger.debug(api_machine)
        image = super(OpenStack_Esh_NodeDriver, self)._to_image(api_machine)
        image.extra['state'] = api_machine['status'].lower()
        image.extra['image_size'] = api_machine['OS-EXT-IMG-SIZE:size']  # NOTE: This may change. keep an eye on this.. -Steve
        image.extra['api'] = api_machine
        return image

    def neutron_set_ips(self, node, floating_ips):
        """
        Using the network manager, find all IPs associated with this node
        """
        for f_ip in floating_ips:
            if f_ip.get('instance_id') == node.id:
                node.public_ips.append(f_ip['floating_ip_address'])
        return
    def neutron_list_networks(self, *args, **kwargs):
        """
        Although there is an 'os-networks' endpoint, valuable information like tenant_id are missing from the return-data, so we must call neutron directly..
        """
        network_manager = self.get_network_manager()
        networks = network_manager.list_networks(*args, **kwargs)
        return networks

    def neutron_get_tenant_network(self):
        network_manager = self.get_network_manager()
        tenant_networks = network_manager.tenant_networks()
        return tenant_networks[0] if tenant_networks else None

    def neutron_list_ports(self, *args, **kwargs):
        network_manager = self.get_network_manager()
        networks = network_manager.list_ports(*args, **kwargs)
        return networks

    def _to_nodes(self, el):
        if 'servers' in el:
            servers = el['servers']
        else:
            servers = el
        return [self._to_node(api_node) for api_node in servers]

    def _to_node(self, api_node, floating_ips=[]):
        """
        Extends OpenStack_1_1_NodeDriver._to_node
        adding support for public and private ips.
        """
        def _set_ips():
            """
            Set up ips in the api_node so _to_node may call its super.
            """
            try:
                public_ips, private_ips = [], []
                for (label, ip_addrs) in api_node['addresses'].items():
                    for ip in ip_addrs:
                        # If OS IP:type floating, assign to public network
                        # All other
                        if ip.get('OS-EXT-IPS:type') == 'floating':
                            public_ips.append(ip['addr'])
                        else:
                            private_ips.append(ip['addr'])
                [node.public_ips.append(ip) for ip in public_ips
                 if ip not in node.public_ips]
                [node.private_ips.append(ip) for ip in private_ips
                 if ip not in node.private_ips]
                #In this special case, it may be a matter of time before the ip
                #is available.. Atmosphere provides a hint with 'public-ip'
                #NOTE: Removed because it was causing problems in production
                #      cloud --Jan. 2015
                if node.private_ips and not node.public_ips \
                        and 'public-ip' in api_node['metadata']:
                    node.public_ips = [api_node['metadata']['public-ip']]
            except (IndexError, KeyError) as no_ip:
                logger.warn("No IP for node:%s" % api_node['id'])
        node = super(OpenStack_Esh_NodeDriver, self)._to_node(api_node)
        if floating_ips:
            self.neutron_set_ips(node, floating_ips)
        else:
            _set_ips()
        node.extra.update({
            'addresses': api_node.get('addresses'),
            'status': api_node.get('status').lower(),
            'fault': api_node.get('fault',{}),
            'task': api_node.get('OS-EXT-STS:task_state'),
            'power': api_node.get('OS-EXT-STS:power_state'),
            'object': api_node
        })
        return node

    def _copy_connection(self, **update_args):
        """
        Use this to copy the connectionObject
        """
        copied_args = {
            "user_id": self.connection.user_id,
            "key": self.key,
            "secret": self.secret,
            "secure": self.connection.secure,
            "host": self.connection.host,
            "port": self.connection.port,
            "timeout": self.connection.timeout,
            "ex_force_base_url": self._ex_force_base_url,
            "ex_force_auth_url": self._ex_force_auth_url,
            "ex_force_auth_version": self._ex_force_auth_version,
            "ex_force_auth_token": self._ex_force_auth_token,
            "ex_tenant_name": self._ex_tenant_name,
            "ex_force_service_type": self._ex_force_service_type,
            "ex_force_service_name": self._ex_force_service_name,
            "ex_force_service_region": self._ex_force_service_region,
        }
        copied_args.update(update_args)
        new_connection = self.__class__(**copied_args)
        return new_connection

    #def _make_keystone_connection(self):
    #    """
    #    Swap base url to make a request against keystone instead of nova
    #    """
    #    return self._copy_connection(
    #        ex_force_service_type='identity',
    #        ex_force_service_name='keystone')

    @swap_service_catalog(service_type="identity", name="keystone")
    def _keystone_list_users(self):
        user_resp = self.connection.request('/users').object
        all_users = user_resp['users']
        return all_users

    def _keystone_get_user(self, username):
        all_users = self._keystone_list_users()
        for user in all_users:
            if user['username'] == username or user['id'] == username:
                return user
        return None

    @swap_service_catalog(service_type="identity", name="keystone")
    def _keystone_list_tenants(self):
        tenant_resp = self.connection.request('/tenants').object
        all_tenants = tenant_resp['tenants']
        return all_tenants

    def _keystone_get_tenant(self, tenant_id_or_name):
        all_tenants = self._keystone_list_tenants()
        for tenant in all_tenants:
            if tenant['id'] == tenant_id_or_name or tenant['name'] == tenant_id_or_name:
                return tenant
        return None

    def _create_args_to_params(self, node, **kwargs):
        """
        NOTE: This is temporary. Latest version of libcloud has
        ex_availability_zone support
        """
        server_params = super(OpenStack_Esh_NodeDriver, self)\
            ._create_args_to_params(node, **kwargs)
        if 'ex_availability_zone' in kwargs:
            server_params['availability_zone'] = kwargs['ex_availability_zone']
        return server_params

    def _boot_volume_args_to_params(self, node, **kwargs):
        server_params = super(OpenStack_Esh_NodeDriver, self)\
            ._create_args_to_params(node, **kwargs)
        #Most of the work is taken care of at this stage...
        #But booting a volume requires some additional work.
        block_device_mapping = {
            "boot_index": kwargs.get("boot_index",0),
            "destination_type": kwargs.get("destination_type"),
            "delete_on_termination": kwargs.get("shutdown",False),
            "volume_size": kwargs.get("volume_size"),
            #NOTE: This line will likely change in icehouse. Replace it with:
            # "shutdown"  : kwargs.get("shutdown", False),
        }
        if kwargs.get('snapshot') and not node:
            block_device_mapping["source_type"] = "snapshot"
            block_device_mapping["uuid"] = kwargs['snapshot'].id
        elif kwargs.get('volume') and not node:
            block_device_mapping["source_type"] = "volume"
            block_device_mapping["uuid"] = kwargs['volume'].id
        elif kwargs.get('image') and not node:
            block_device_mapping["source_type"] = "image"
            block_device_mapping["uuid"] = kwargs['image'].id
        else:
            raise ValueError("To boot a volume, you must select a source."
                    " Available Sources: [image, volume, snapshot]")


        #NOTE: Wrapped in a list
        server_params["block_device_mapping_v2"] = [block_device_mapping]
        return server_params

    def create_node(self, **kwargs):
        """
        Helpful arguments to set:
        ex_keyname : Name of existing public key
        ex_availability_zone : Name of host to launch on
        ex_connection_kwargs : A dictionary of kwargs to be passed to the connection.
        """
        conn_kwargs = kwargs.pop('ex_connection_kwargs', {})
        server_params = self._create_args_to_params(None, **kwargs)

        resp = self.connection.request("/servers",
                                       method='POST',
                                       data={'server': server_params},
                                       **conn_kwargs)

        create_response = resp.object['server']
        server_resp = self.connection.request(
            '/servers/%s' % create_response['id'])
        server_object = server_resp.object['server']

        # adminPass is not always present
        # http://docs.openstack.org/essex/openstack-compute/admin/
        # content/configuring-compute-API.html#d6e1833
        server_object['adminPass'] = create_response.get('adminPass', None)

        node = self._to_node(server_object)

        return node

    def reboot_node(self, node, reboot_type='SOFT'):
        """
        Options for 'reboot_type': SOFT, HARD
        """
        return self._reboot_node(node, reboot_type=reboot_type)

    def ex_create_node_with_network(self, **kwargs):
        """
        Deprecated -- Old Workflow (Via JMATT!)
        """
        self._add_keypair(kwargs)
        kwargs.update({
            'ex_keyname': unicode(self.key),
        })
        logger.debug("kwargs = %s" % kwargs)
        #Instance launches at this point.
        node = super(OpenStack_Esh_NodeDriver, self).create_node(**kwargs)

        #NOTE: This line is needed to authenticate via SSH_Keypair instead!
        node.extra['password'] = None

        #NOTE: Using this to wait for the time it takes to launch
        # instance and have a valid IP port
        time.sleep(20)
        #TODO: It would be better to hook in an asnyc thread that
        # waits for valid IP port
        #TODO: This belongs in a eelery task.
        #server_id = node.id
        self.neutron_associate_ip(node, **kwargs)

        return node

    def ex_deploy_to_node(self, node, *args, **kwargs):
        """
        libcloud.compute.base.deploy_node
        """
        if not libcloud.compute.ssh.have_paramiko:
            raise RuntimeError('paramiko is not installed. You can install ' +
                               'it using pip: pip install paramiko')

        password = None

        if 'create_node' not in self.features:
            raise NotImplementedError(
                'deploy_node not implemented for this driver')
        elif 'generates_password' not in self.features["create_node"]:
            if 'password' not in self.features["create_node"] and \
               'ssh_key' not in self.features["create_node"]:
                raise NotImplementedError(
                    'deploy_node not implemented for this driver')

            if 'auth' not in kwargs:
                value = os.urandom(16)
                kwargs['auth'] = NodeAuthPassword(binascii.hexlify(value))

            if 'ssh_key' not in kwargs:
                password = kwargs['auth'].password

        max_tries = kwargs.get('max_tries', 3)

        if 'generates_password' in self.features['create_node']:
            password = node.extra.get('password')

        ssh_interface = kwargs.get('ssh_interface', 'public_ips')

        # Wait until node is up and running and has IP assigned
        try:
            node, ip_addresses = self.wait_until_running(
                nodes=[node],
                wait_period=3, timeout=NODE_ONLINE_WAIT_TIMEOUT,
                ssh_interface=ssh_interface)[0]
            if not ip_addresses:
                raise Exception('IP address was not found')
            logger.info("Ip Address found after calling wait_until_running: %s"
                        % ip_addresses)
        except Exception:
            e = sys.exc_info()[1]
            raise DeploymentError(node=node, original_exception=e, driver=self)

        if password:
            node.extra['password'] = password

        deploy_task = kwargs['deploy']
        ssh_username = kwargs.get('ssh_username', 'root')
        ssh_alternate_usernames = kwargs.get('ssh_alternate_usernames', [])
        ssh_port = kwargs.get('ssh_port', 22)
        ssh_timeout = kwargs.get('ssh_timeout', 10)
        ssh_key_file = kwargs.get('ssh_key', None)
        timeout = kwargs.get('timeout', SSH_CONNECT_TIMEOUT)

        deploy_error = None
        for username in ([ssh_username] + ssh_alternate_usernames):
            try:
                self._connect_and_run_deployment_script(
                    task=deploy_task, node=node,
                    ssh_hostname=ip_addresses[0], ssh_port=ssh_port,
                    ssh_username=username, ssh_password=password,
                    ssh_key_file=ssh_key_file, ssh_timeout=ssh_timeout,
                    timeout=timeout, max_tries=max_tries)
            except Exception as exc:
                # Try alternate username
                # TODO: Need to fix paramiko so we can catch a more specific
                # exception
                logger.exception("Could not connect to SSH on IP address %s" %
                                 ip_addresses[0])
                e = sys.exc_info()[1]
                deploy_error = e
            else:
                # Script sucesfully executed, don't try alternate username
                deploy_error = None
                break
        if deploy_error is not None:
            raise DeploymentError(node=node, original_exception=deploy_error,
                                  driver=self)
        if isinstance(deploy_task, ScriptDeployment):
            deploy_steps = [deploy_task]
        elif isinstance(deploy_task, MultiStepDeployment):
            deploy_steps = deploy_task.steps
        else:
            #No additional validation necessary for other types of deployment.
            return node
        #Additional validation for Script Deployments
        failed_steps = []
        for deploy_step in deploy_steps:
            if deploy_step.exit_status != 0:
                failed_steps.append(
                    "Script:%s returned a Non-Zero exit"
                    " status:%s. Stdout:%r Stderr:%r"
                    % (deploy_step.name, deploy_step.exit_status,
                       deploy_step.stdout, deploy_step.stderr))
        if failed_steps and not kwargs.get('non_zero_deploy'):
            raise DeploymentError(
                original_exception=NonZeroDeploymentException(
                    str(failed_steps)),
                node=node, driver=self)
        return node

    def _ssh_client_connect(self, ssh_client, wait_period=1.5, timeout=300):
        """
        Try to connect to the remote SSH server. If a connection times out or
        is refused it is retried up to timeout number of seconds.

        @keyword    ssh_client: A configured SSHClient instance
        @type       ssh_client: C{SSHClient}

        @keyword    wait_period: How many seconds to wait between each loop
                                 iteration (default is 1.5)
        @type       wait_period: C{int}

        @keyword    timeout: How many seconds to wait before timing out
                             (default is 600)
        @type       timeout: C{int}

        @return: C{SSHClient} on success
        """
        start = time.time()
        end = start + timeout

        while time.time() < end:
            try:
                ssh_client.connect(ignore_hosts=True)
            except (IOError, socket.gaierror, socket.error):
                # Retry if a connection is refused or timeout
                # occurred
                ssh_client.close()
                time.sleep(wait_period)
                continue
            else:
                return ssh_client

        raise LibcloudError(value='Could not connect to the remote SSH ' +
                            'server. Giving up.', driver=self)

    def _connect_and_run_deployment_script(self, task, node, ssh_hostname,
                                           ssh_port, ssh_username,
                                           ssh_password, ssh_key_file,
                                           ssh_timeout, timeout, max_tries):
        ssh_client = FabricSSHClient(hostname=ssh_hostname,
                                     port=ssh_port, username=ssh_username,
                                     password=ssh_password,
                                     key=ssh_key_file,
                                     timeout=ssh_timeout)

        # Connect to the SSH server running on the node
        logger.info(ssh_client.__dict__)
        ssh_client = self._ssh_client_connect(ssh_client=ssh_client,
                                              timeout=timeout)

        # Execute the deployment task
        self._run_deployment_script(task=task, node=node,
                                    ssh_client=ssh_client,
                                    max_tries=max_tries)

    def _run_deployment_script(self, task, node, ssh_client, max_tries=3):
        """
        Run the deployment script on the provided node. At this point it is
        assumed that SSH connection has already been established.

        @keyword    task: Deployment task to run on the node.
        @type       task: C{Deployment}

        @keyword    node: Node to operate one
        @type       node: C{Node}

        @keyword    ssh_client: A configured and connected SSHClient instance
        @type       ssh_client: C{SSHClientunlink

        @keyword    max_tries: How many times to retry if a deployment fails
                               before giving up (default is 3)
        @type       max_tries: C{int}

        @return: C{Node} Node instance on success.
        """
        tries = 0
        while tries < max_tries:
            try:
                node = task.run(node, ssh_client)
            except Exception:
                e = sys.exc_info()[1]
                tries += 1
                if tries >= max_tries:
                    e = sys.exc_info()[1]
                    raise LibcloudError(value='Failed after %d tries: %s'
                                        % (max_tries, str(e)), driver=self)
            else:
                return node
            finally:
                ssh_client.close()

    def ex_start_node(self, node):
        """
        Suspend a node.
        """
        resp = self._node_action(node, 'os-start')
        return resp.status == httplib.ACCEPTED

    def ex_stop_node(self, node):
        """
        Suspend a node.
        """
        resp = self._node_action(node, 'os-stop')
        return resp.status == httplib.ACCEPTED

    def ex_get_tenant_network(self, tenant_id):
        networks = self.ex_list_networks()
        tenant_network = [net for net in networks if tenant_id == net.tenant_id]
        return tenant_network

    def ex_suspend_node(self, node):
        """
        Suspend a node.
        """
        resp = self._node_action(node, 'suspend')
        return resp.status == httplib.ACCEPTED

    def ex_reset_network(self, node):
        """
        Resume a node.
        """
        resp = self._node_action(node, 'resetNetwork')
        return resp.status == httplib.ACCEPTED

    def ex_resume_node(self, node):
        """
        Resume a node.
        """
        resp = self._node_action(node, 'resume')
        return resp.status == httplib.ACCEPTED

    def ex_vnc_console(self, node, vnc_type='novnc'):
        """
        Return a novnc token and url for a node.
        Optional vnc_types:
        * novnc (Default - For Web Clients)
        * xvpvnc (For Java Clients)
        """
        resp = self._node_action(node,
                                 'os-getVNCConsole',
                                 type=vnc_type)
        return json.loads(resp.body)['console']['url']

    #quotas
    def _establish_connection(self):
        """
        This function will contact keystone for authorization
        and make an empty request to the server.

        Doing this will provide self.connection.auth_token.
        """
        try:
            self.connection.request('')
        except:
            #Will fail,but we MUST make a request to authenticate
            pass

    def _get_username(self):
        #if not self.connection.auth_token:
        #    self._establish_connection()
        return self.key

    def _get_user_id(self):
        if not self.connection.auth_token:
            self._establish_connection()
        return self.connection.auth_token.get('id')

    def _get_tenant_id(self):
        """
        After a successful auth, the 'action' will be:
        /v2/<tenant_id>
        We are parsing the action to retrieve the tenant_id.
        """
        if not self.connection.auth_token:
            self._establish_connection()
        action_str = self.connection.action
        if not action_str or len(action_str.split('/')) < 2:
            return None
        return self.connection.action.split("/")[2]

    #Volume Snapshots
    def ex_list_snapshots(self):
        """
        List the current users snapshots
        """
        server_resp = self.connection.request(
                '/os-snapshots')
        return [self._to_snapshot(snapshot)
                for snapshot in server_resp.object['snapshots']]

    @swap_service_catalog(service_type="volume", name="cinder")
    def ex_create_snapshot(self, display_name, display_description,
                           volume_id, force=True, tenant_id=None):
        """
        """
        body = {
            'snapshot': {
                "display_name": display_name,
                "display_description": display_description,
                "volume_id": volume_id,
                "force": force
            }
        }
        if tenant_id:
            body['tenant_id'] = tenant_id
        server_resp = self.connection.request(
                '/snapshots',
                data=body,
                method='POST')
        return self._to_snapshot(server_resp.object)

    @swap_service_catalog(service_type="volume", name="cinder")
    def ex_list_all_snapshots(self):
        """
        Admins only
        """
        server_resp = self.connection.request(
                '/snapshots/detail?all_tenants=1')
        return [self._to_snapshot(snapshot)
                for snapshot in server_resp.object['snapshots']]

    def ex_get_snapshot(self, snapshot_id):
        server_resp = self.connection.request(
                '/os-snapshots/%s' % snapshot_id)
        return self._to_snapshot(server_resp.object)

    #Volumes
    def ex_boot_volume(self, **kwargs):
        """
        """
        #Strict Validation required for some values..
        #1. if booting by something that is NOT a volume (Snapshot/Image)
        #   the size of the new volume must be created.
        logger.debug("driver.ex_boot_volume kwargs: %s" % kwargs)

        if not kwargs.get('volume') and not kwargs.get('volume_size'):
            raise ValueError(
                    "Conflict: Must define an explicit volume_size "
                    "when the source is not a volume")

        #Until we have a reason to support the 'local' and 'None' destination..
        if not kwargs.has_key("destination_type"):
            kwargs['destination_type'] = 'volume'

        server_params = self._boot_volume_args_to_params(None, **kwargs)
        server_resp = self.connection.request('/os-volumes_boot',
                                              method='POST',
                                              data={'server': server_params})
        return (server_resp.status == 200, server_resp.object)

    @swap_service_catalog(service_type="volume", name="cinder")
    def create_volume(self, size, name,
                      description=None, metadata=None,
                      location=None, snapshot=None, image=None, **connection_kwargs):
        """
        Create a new volume

        @keyword size: The size of the new volume
        @type    size: C{int}

        @keyword name: The name of the new volume
        @type    name: C{str}

        @keyword description: A description for the new volume (Optional)
        @type    description: C{str}

        @param   metadata: Key/Value metadata to associate with a node
        @type    metadata: C{dict}

        @keyword location: The location to place the new volume (Optional)
        @type    location: C{str}

        @keyword snapshot: Create a new volume from existing snapshot (Optional)
        @type    snapshot: C{VolumeSnapshot}

        @keyword image: Create a new volume from existing image (Optional)
        @type    image: C{Image}
        """
        body = {'volume': {
            'size': size,
            'display_name': name,
            }
        }
        if description:
            body['volume']['display_description'] = description
        if location:
            body['volume']['availability_zone'] = location
        if snapshot:
            body['volume']['snapshot_id'] = snapshot.id
        if image:
            body['volume']['imageRef'] = image.id
        server_resp = self.connection.request('/volumes',  # v3 doesnt use os-volumes anymore
                                              method='POST',
                                              data=body, **connection_kwargs)
        volume_obj =  self._to_volume(server_resp.object, cinder=True)
        return (server_resp.success(), volume_obj)

    def list_volumes(self):
        return self._to_volumes(self.connection.request("/os-volumes").object)

    def ex_volume_attached_to_instance(self, volume, instance_id):
        if not volume:
            return False
        attach_data = volume.extra.get('attachments', [])
        for attachment in attach_data:
            attached_instance_id = attachment.get('serverId')
            if not attached_instance_id:
                continue
            if attached_instance_id == instance_id:
                return True
        return False

    def ex_list_all_sizes(self):
        """
        List all instances from all tenants of a user
        """
        server_resp = self.connection.request(
            '/flavors/detail?all_tenants=1',
            method='GET')
        return self._to_sizes(server_resp.object)

    def ex_list_all_instances(self):
        """
        List all instances from all tenants of a user
        """

        def build_query_params(all_tenants, limit, marker=None):
            return "all_tenants={}".format("True" if all_tenants else "False") + \
                "&limit={}".format(limit) + \
                ("&marker={}".format(marker) if marker else "")

        # Atmosphere depends on the fact that this fetches all instances for a
        # tenant, but all tenants' instances for admin tenants. Hacky, but
        # easy enough to fix.
        all_tenants = self.key in ['atmoadmin', 'admin']
        non_pagination_timeout = 5 * 60 if all_tenants else 60
        limit = 500
        query_params = build_query_params(all_tenants, limit)
        current_server_set = set()
        servers = []

        while True:
            response = self.connection.request(
                "/servers/detail?" + query_params
            )
            data = response.object
            servers.extend(data['servers'])

            new_server_set = {s['id'] for s in data['servers']}
            if current_server_set.intersection(new_server_set):
                logger.error(
                    "The compute api is returning duplicates in its "
                    "pagination logic when fetching all instances. We are "
                    "going to workaround this issue and fetch all instances "
                    "without pagination"
                )

                # Make a non-paginated request with an exceptionally large
                # timeout
                old_timeout = self.connection.timeout
                self.connection.timeout = non_pagination_timeout
                response = self.connection.request(
                    "/servers/detail?" + "all_tenants=True"
                    if all_tenants else "",
                    max_attempts=1
                )
                self.connection.timeout = old_timeout
                data = response.object
                servers = data['servers']
                break
            current_server_set.update(new_server_set)

            # It would be smarter to just check if len < limit. In practice
            # the compute apis sometimes return less than page limit even when
            # more pages exist
            if not len(data['servers']):
                break

            last_server = data['servers'][-1]
            query_params = build_query_params(
                all_tenants, limit, marker=last_server["id"]
            )

        return self._to_nodes({'servers': servers})

    @swap_service_catalog(service_type="network", name="neutron")
    def _neutron_delete_quota(self, tenant_id):
        if not tenant_id:
            raise Exception("Tenant ID required to delete neutron quota")
        server_resp = self.connection.request(
            '/v2.0/quotas/%s.json' % tenant_id,
            method='DELETE')
        return server_resp.status == 204

    @swap_service_catalog(service_type="network", name="neutron")
    def _neutron_update_quota(self, tenant_id, new_values):
        if not tenant_id:
            raise Exception("Tenant ID required to update neutron quota")
        # Check for 'quota' wrapper
        if 'quota' not in new_values:
            new_values = {'quota': new_values}
        resp = self.connection.request(
            '/v2.0/quotas/%s.json' % tenant_id,
            data=new_values,
            method='PUT')
        quota = resp.object['quota']
        return quota

    @swap_service_catalog(service_type="network", name="neutron")
    def _neutron_show_quota(self, tenant_id=None):
        # If no tenant ID - use your own tenant ID
        tenant_resp = self.connection.request('/v2.0/quotas/tenant.json')
        tenant_obj = tenant_resp.object
        tenant_id = tenant_obj.get('tenant', {}).get('tenant_id', None)
        if not tenant_id:
            raise Exception("Error calling /v2.0/quotas/tenant.json - %s" % tenant_obj)
        # call to show quota:
        resp = self.connection.request('/v2.0/quotas/%s.json' % tenant_id)
        quota = resp.object['quota']
        return quota

    @swap_service_catalog(service_type="volume", name="cinder")
    def _cinder_delete_quota(self, username):
        lc_conn = self.connection
        server_resp = lc_conn.request(
            '/os-quota-sets/%s' % username,
            method='DELETE')
        return server_resp.status == 204

    @swap_service_catalog(service_type="volume", name="cinder")
    def _cinder_update_quota(self, username, new_values):
        lc_conn = self.connection
        # Check for 'quota_set' wrapper
        if 'quota_set' not in new_values:
            new_values = {'quota_set': new_values}
        server_resp = lc_conn.request(
            '/os-quota-sets/%s' % username,
            data=new_values,
            method='PUT')
        return server_resp.object.get('quota_set',{})


    @swap_service_catalog(service_type="volume", name="cinder")
    def _cinder_show_quota(self, username):
        lc_conn = self.connection
        server_resp = lc_conn.request(
            '/os-quota-sets/%s' % username,
            method='GET')
        return server_resp.object.get('quota_set',{})


    @swap_service_catalog(service_type="volume", name="cinder")
    def ex_list_all_volumes(self):
        lc_conn = self.connection
        server_resp = lc_conn.request(
            '/volumes/detail?all_tenants=1',
            method='GET')
        return self._to_volumes(server_resp.object, cinder=True)


    @swap_service_catalog(service_type="volume", name="cinder")
    def ex_update_volume(self, volume, **volume_updates):
        """
        Updates the editable attributes of a volume,
        Including: display_name, display_description
        For metadata, see 'ex_update_volume_metadata'
        """
        #ARGS formatting
        if 'name' in volume_updates:
            volume_updates['display_name'] = \
                    volume_updates.pop('name')
        elif 'displayName' in volume_updates:
            volume_updates['display_name'] = \
                    volume_updates.pop('displayName')
        if 'description' in volume_updates:
            volume_updates['display_description'] = \
                    volume_updates.pop('description')
        elif 'displayDescription' in volume_updates:
            volume_updates['display_description'] = \
                    volume_updates.pop('displayDescription')

        server_resp = self.connection.request(
                '/volumes/%s' % volume.id,
                method='PUT', data={'volume':volume_updates},
                )
        return self._to_volume(server_resp.object['volume'], cinder=True)

    @swap_service_catalog(service_type="volume", name="cinder")
    def ex_update_volume_metadata(self, volume, metadata):
        """
        Volume Metadata update
        metadata == dict of key/value metadata to be associated
        """
        data_dict = {'metadata': metadata}
        server_resp = self.connection.request('/volumes/%s/metadata' % volume.id,
                                              method='PUT',
                                              data=data_dict)
        try:
            return (server_resp.status == 200, server_resp.object['metadata'])
        except Exception, e:
            logger.exception("Exception occured updating volume")
            return (False, None)

    @swap_service_catalog(service_type="volume", name="cinder")
    def ex_delete_volume_metadata_key(self, volume, metadata_key):
        """
        """
        server_resp = self.connection.request(
                '/volumes/%s/metadata/%s' % (volume.id, metadata_key),
                method='DELETE')
        try:
            return server_resp.status == 200
        except Exception, e:
            logger.exception("Exception occured Removing Volume Metadata."
                             " Offending Key=%s" % metadata_key)
            return False


    def ex_list_volume_attachments(self, node):
        """
        List all attached/attaching volumes for a specific node
        """
        server_id = node.id
        server_resp = self.connection.request(
            '/servers/%s/os-volume_attachments' % server_id,
            method='GET')
        return server_resp.object.get('volumeAttachments', {})

    def ex_get_volume_attachment(self, volume):
        """
        Get details for specific volume attachment on a node
        """
        server_id = volume.attachment_set[0].get('serverId')
        attachment_id = volume.attachment_set[0].get('id')
        server_resp = self.connection.request(
            '/servers/%s/os-volume_attachments/%s' %
            (server_id, attachment_id),
            method='GET')
        return server_resp.object

    def ex_lookup_hypervisor_id_by_name(self, hypervisor_name):
        matches = [hv['id'] for hv in self.ex_list_hypervisor_nodes()
                   if hv['hypervisor_hostname'] == hypervisor_name]
        if not matches:
            raise ValueError("Hypervisor name %s has no corresponding ID.")
        return matches[0]

    def ex_list_instances_on_node(self, node_id):
        if type(node_id) == str:
            node_id = self.ex_lookup_hypervisor_id_by_name(node_id)
        return self.connection.request(
            "/os-hypervisors/%s/servers" % node_id).object['hypervisors']

    def ex_list_hypervisor_nodes(self):
        return self.connection.request(
            "/os-hypervisors").object['hypervisors']

    def ex_detail_hypervisor_nodes(self):
        return self.connection.request(
            "/os-hypervisors/detail").object['hypervisors']

    def ex_detail_hypervisor_node(self, node_id):
        if type(node_id) == str:
            node_id = self.ex_lookup_hypervisor_id_by_name(node_id)
        return self.connection.request(
            "/os-hypervisors/%s" % node_id).object['hypervisor']

    def ex_hypervisor_statistics(self):
        return self.connection.request(
            "/os-hypervisors/statistics").object['hypervisor_statistics']

    #Floating IPs
    def ex_list_floating_ips(self, region=None, **kwargs):
        """
        List all floating IPs in the tenants pool
        """
        def _to_ips(ip_list):
            return [floating_ip for floating_ip in ip_list['floating_ips']]
        try:
            return _to_ips(self.connection.request("/os-floating-ips").object)
        except:
            logger.warn("Unable to list floating ips from nova.")
            return []

    def ex_allocate_floating_ip(self, pool_name, **kwargs):
        """
        Allocate a new floating IP address to the tenants pool
        """
        try:
            floating_ip_obj = self.connection.request(
                '/os-floating-ips', method='POST',
                data={'pool': pool_name}).object
            return floating_ip_obj['floating_ip']
        except Exception, e:
            raise

    def ex_deallocate_floating_ip(self, floating_ip, **kwargs):
        """
        Deallocate an existing floating_ip from tenants pool
        """
        try:
            server_resp = self.connection.request(
                '/os-floating-ips/%s' % floating_ip,
                method='DELETE')
            return server_resp.object
        except Exception, e:
            raise

    def ex_clean_floating_ip(self, **kwargs):
        """
        Check for floating IPs without an instance ID
        and remove them from the driver
        """
        count = 0
        for f_ip in self.ex_list_floating_ips():
            if not f_ip.get('instance_id'):
                self.ex_deallocate_floating_ip(f_ip['id'])
                count += 1
        return count

    def ex_bulk_delete_floating_ips(self, ip_range):
        """
        Deallocate an existing floating_ip from tenants pool
        """
        try:
            # NOTE: the docs show this (in newer openstack?) as:
            # http://developer.openstack.org/api-ref-compute-v2-ext.html#DeleteFloatingIPBulk
            # data = {"ip_range":ip_range}
            data = {"floating_ips_bulk_delete": ip_range}
            server_resp = self.connection.request(
                '/os-floating-ips-bulk/delete',
                method='POST', data=data)
            return server_resp.object
        except Exception, e:
            raise

    def ex_bulk_create_floating_ips(self, ip_range, pool="nova", interface="eth0"):
        """
        Deallocate an existing floating_ip from tenants pool
        """
        try:
            data = {"floating_ips_bulk_create": {
                "ip_range": ip_range,
                "pool": pool,
                "interface":interface
                }}
            server_resp = self.connection.request(
                '/os-floating-ips-bulk',
                method='POST', data=data)
            return server_resp.object
        except Exception, e:
            raise

    def ex_add_fixed_ip(self, server, network_id):
        """
        """
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server.id,
                method='POST',
                data={'addFixedIp': {'networkId': network_id}})
            return server_resp.object
        except Exception, e:
            raise

    def ex_remove_fixed_ip(self, server, fixed_ip_addr):
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server.id,
                method='POST',
                data={'removeFixedIp': {'address': fixed_ip_addr}})
            return server_resp.object
        except Exception, e:
            raise

    def ex_associate_floating_ip(self, server, address, **kwargs):
        """
        Associate an allocated floating IP to the node
        """
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server.id,
                method='POST',
                data={'addFloatingIp': {'address': address}})
            return server_resp.object
        except Exception, e:
            raise

    def ex_disassociate_floating_ip(self, server, address=None, **kwargs):
        """
        Disassociate a floating IP that's been associated to the node
        """
        try:
            if not address:
                public_ips = server._node.public_ips
                if not public_ips:
                    logger.warn("Could not determine public IP address,\
                    please provide the floating IP address")
                    return None
                address = public_ips[0]
            if not address:
                logger.warn("No public IP address found for instance %s", server.id)
                return None
            server_resp = self.connection.request(
                '/servers/%s/action' % server.id,
                method='POST',
                data={'removeFloatingIp': {'address': address}})
            return server_resp.object
        except Exception, e:
            raise

    #Security Groups
    def ex_add_security_group(self, server, sec_group, **kwargs):
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server.id,
                method='POST',
                data={'addSecurityGroup': {'name': sec_group.name}})
            return server_resp.object
        except Exception, e:
            raise

    def ex_remove_security_group(self, server, sec_group):
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server.id,
                method='POST',
                data={'removeSecurityGroup': {'name': sec_group.name}})
            return server_resp.object
        except Exception, e:
            raise


    #API Limits
    def ex_get_limits(self):
        """
        _to_rate and _to_absolute
        """
        def _to_rate(el):
            rate_limits = el.get('limits', {}).get('rate', [])
            limit_dict = {}
            for a_limit in rate_limits:
                rest_dict = {}
                for rest_limit in a_limit['limit']:
                    r_limit_map = {}
                    r_limit_map['call_available'] = rest_limit['value']
                    r_limit_map['call_limit'] = rest_limit['remaining']
                    r_limit_map['duration'] = rest_limit['unit']
                    r_limit_map['limit_expiry'] = rest_limit['next-available']
                    rest_dict[rest_limit['verb']] = r_limit_map
                limit_dict[a_limit['uri']] = rest_dict
            return limit_dict

        def _to_absolute(el):
            return el.get('limits', {}).get('absolute', {})

        json_limits = self.connection.request("/limits").object
        rate = _to_rate(json_limits)
        absolute = _to_absolute(json_limits)
        return {"rate": rate, "absolute": absolute}

    def ex_detach_interface(self, instance_id, port_id):
        """
        Detaches an existing fixed IP address (port) with ta server (Device)
        See:
            http://docs.openstack.org/api/openstack-compute/2/content/ext-os-interface.html
        """
        uri = "/servers/%s/os-interface/%s" % (instance_id, port_id)
        server_resp = self.connection.request(uri, method="DELETE")
        return server_resp.status == 202


    def ex_attach_interface(self, instance_id, network_id=None, port_id=None):
        """
        Attaches an existing fixed IP address (port) with ta server (Device)
        See:
            http://docs.openstack.org/api/openstack-compute/2/content/ext-os-interface.html
        """
        uri = "/servers/%s/os-interface" % (instance_id,)
        if not network_id and not port_id:
            raise Exception("Missing required argument: port_id OR network_id")
        elif network_id and port_id:
            raise Exception("Too many arguments: port_id OR network_id")
        elif port_id:
            attach_data = {"port_id":port_id }
        elif network_id:
            attach_data = {"net_id":network_id }

        server_resp = self.connection.request(uri, method="POST",
                data={"interfaceAttachment": attach_data})
        return server_resp.object['interfaceAttachment']

    def ex_os_services(self):
        """
        Return a list of services with their current state and status.

        See: http://docs.openstack.org/api\
             /openstack-compute/2/content/ext-os-services.html
        """
        uri = "/os-services"
        return self.connection.request(uri, method="GET").object["services"]

    """
    Private methods
    While these methods are useful,
    they will NOT be included when we push back to libcloud..
    """
    def neutron_associate_ip(self, node, *args, **kwargs):
        """
        Add IP (Neutron)
        There is no good way to interface libcloud + nova + neutron,
        instead we call neutronclient directly..
        Feel free to replace when a better mechanism comes along..
        """

        try:
            network_manager = self.get_network_manager()
            floating_ip = network_manager.associate_floating_ip(node.id)
        except NeutronClientException as q_error:
            if q_error.status_code == 409:
                #409 == Conflict
                #Lets look through the message and determine why:
                logger.info("Conflict stopped node from associating new "
                            "floating IP. Message=%s" % q_error.message)
            #Handle any conflicts that make sense and return, all others:
            raise

        return floating_ip

    def neutron_list_ips(self, node, *args, **kwargs):
        """
        List IP (Neutron)
        There is no good way to interface libcloud + nova + neutron,
        instead we call neutronclient directly..
        Feel free to replace when a better mechanism comes along..
        """

        try:
            network_manager = self.get_network_manager()
            floating_ips = network_manager.list_floating_ips()
        except NeutronClientException as q_error:
            if q_error.status_code == 409:
                #409 == Conflict
                #Lets look through the message and determine why:
                logger.info("Conflict stopped node from associating new "
                            "floating IP. Message=%s" % q_error.message)
            #Handle any conflicts that make sense and return, all others:
            raise
        ip_list = []
        for f_ip in floating_ips:
            if f_ip.get('instance_id') == node.id:
                ip_list.append(f_ip)
        return ip_list

    def get_user_manager(self):
        return UserManager.lc_driver_init(self)

    def get_network_manager(self):
        return NetworkManager.lc_driver_init(self)

    def neutron_disassociate_ip(self, node, *args, **kwargs):
        """
        Remove IP (Neutron)
        There is no good way to interface libcloud + nova + neutron,
        instead we call neutronclient directly..
        Feel free to replace when a better mechanism comes along..
        """

        try:
            network_manager = self.get_network_manager()
            network_manager.disassociate_floating_ip(node.id)
        except NeutronClientException as q_error:
            if q_error.status_code == 409:
                #409 == Conflict
                #Lets look through the message and determine why:
                logger.info("Conflict stopped node from disassociating new "
                            "floating IP. Message=%s" % q_error.message)
            #Handle any conflicts that make sense and return, all others:
            raise

        return True

    def _image_size(self, image):
        byte_size = image.extra['api']['OS-EXT-IMG-SIZE:size']
        in_gb = byte_size/1024**3
        return in_gb

    def ex_delete_ports(self, node, *args, **kwargs):
        """
        Delete Ports related to node. (Neutron)
        There is no good way to interface libcloud + nova + neutron,
        instead we use neutronclient directly..
        Hopefully Openstack provides a better option soon.
        """
        network_manager = NetworkManager.lc_driver_init(self)
        ports = network_manager.find_server_ports(node.id)
        for p in ports:
            network_manager.delete_port(p)

    # Metadata
    def ex_write_metadata(self, node, metadata, replace_metadata=True):
        """
        NOTE: Similar to ex_set_metadata, but allows for the option
        to KEEP existing metadata by setting 'replace_metadata=False'
        """
        #NOTE: PUT will REPLACE metadata each time it is added
        #      while POST will keep metadata that does not match
        #      The default for libcloud is to replace/override tags.
        # Ex:
        #     {'name': 'test_name'} + PUT {'tags': 'test_tag'}
        #     = {'tags': 'test_tag'}
        #     {'name': 'test_name'} + POST {'tags': 'test_tag'}
        #     = {'name': 'test_name', 'tags': 'test_tag'}
        #
        #
        method = 'PUT' if replace_metadata else 'POST'
        return self.connection.request(
            '/servers/%s/metadata' % (node.id,), method=method,
            data={'metadata': metadata}
        ).object['metadata']


    def ex_get_metadata(self, node, key=None):
        """
        Get a Node's metadata.

        @param      node: Node
        @type       node: L{Node}

        @param      key: Key associated with node's metadata.
        @type       node: L{str}

        @return: Key/Value metadata associated with node.
        @rtype: C{dict}
        """
        response = self.connection.request(
            '/servers/%s/metadata%s' % (node.id, '/%s' if key else ''),
            method='GET',)
        metadata = response.object['metadata']
        return metadata

    def ex_delete_metadata(self, node, key):
        """
        Sets the Node's metadata for a key.

        @param      node: Node
        @type       node: L{Node}

        @param      key: Key associated with node's metadata.
        @type       node: L{str}

        @rtype: C{bool}
        """
        resp = self.connection.request(
            '/servers/%s/metadata/%s' % (node.id, key,),
            method='DELETE')
        return resp.status == httplib.NO_CONTENT

    def ex_get_image_metadata(self, image, key):
        """
        Get an Image's metadata.

        @param      image: Image
        @type       image: L{Image}

        @param      key: Key associated with node's metadata.
        @type       node: L{str}

        @return: Key/Value metadata associated with an image.
        @rtype: C{dict}
        """
        response = self.connection.request(
            '/images/%s/metadata/%s' % (image.id, key,),
            method='GET',)
        metadata = response.object['metadata']
        return metadata

    def ex_get_image_metadata(self, image):
        """
        Get an Image's metadata.

        @param      image: Image
        @type       image: L{Image}

        @return: Key/Value metadata associated with an image.
        @rtype: C{dict}
        """
        response = self.connection.request(
            '/images/%s/metadata' % (image.id,),
            method='GET',)
        metadata = response.object['metadata']
        return metadata

    def ex_set_image_metadata(self, image, metadata):
        """
        Sets the Image's metadata.

        @param      image: Image
        @type       image: L{Image}

        @param      metadata: Key/Value metadata to associate with an image
        @type       metadata: C{dict}

        @rtype: C{dict}
        """
        return self.connection.request(
            '/images/%s/metadata' % (image.id,), method='POST',
            data={'metadata': metadata}
        ).object['metadata']

    def ex_replace_image_metadata(self, image, metadata):
        """
        Sets the Image's metadata.

        @param      image: Image
        @type       image: L{Image}

        @param      metadata: Key/Value metadata to associate with an image
        @type       metadata: C{dict}

        @rtype: C{dict}
        """
        self._json_safe_meta_values(metadata)
        return self.connection.request(
            '/images/%s/metadata' % (image.id,), method='PUT',
            data={'metadata': metadata}
        ).object['metadata']

    def ex_delete_image_metadata(self, image, key):
        """
        Deletes the Image's metadata for a key.

        @param      node: Image
        @type       node: L{Image}

        @param      key: Key associated with image's metadata.
        @type       node: L{str}

        @rtype: C{bool}
        """
        resp = self.connection.request(
            '/images/%s/metadata/%s' % (image.id, key,),
            method='DELETE')
        return resp.status == httplib.NO_CONTENT

    #Server Shelve Actions
    def ex_shelve_instance(self, server, **kwargs):
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server.id,
                method='POST',
                data={'shelve': None})
            return server_resp.object
        except Exception, e:
            raise

    def ex_unshelve_instance(self, server):
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server.id,
                method='POST',
                data={'unshelve': None})
            return server_resp.object
        except Exception, e:
            raise

    def ex_shelve_offload_instance(self, server):
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server.id,
                method='POST',
                data={'shelveOffload': None})
            return server_resp.object
        except Exception, e:
            raise

    def ex_list_quota_for_user(self, user_id, tenant_id):
       """
       Shows quota for user and tenant_id combinations
       @keyword user_id: User ID to update. Typically a UUID.
       @type    user_id: C{str}
       @keyword tenant_id: Tenant or Project ID to update. Typically a UUID.
       @type    tenant_id: C{str}
       """
       server_resp = self.connection.request('/os-quota-sets/%s?user_id=%s'
                                             % (tenant_id, user_id))
       try:
           quota_obj = server_resp.object
           return (server_resp.status == 200, quota_obj)
       except Exception, e:
           logger.exception("Exception occured updating quota. Body:%s"
                            % body)
           return (False, None)

    def ex_update_quota(self, tenant_id, values, use_tenant_id=True):
       """
       Updates value/values in quota set
       @keyword tenant_id: Tenant or Project ID to update. Typically a UUID.
       @type    tenant_id: C{str}
       @keyword values: A Dict containing the new key/value for quota set
       @type    values: C{dict}
       """
       if use_tenant_id:
           values['tenant_id'] = tenant_id
       body = {'quota_set': values}
       server_resp = self.connection.request('/os-quota-sets/%s'
                                             % (tenant_id,),
                                             method='PUT',
                                             data=body)
       try:
           quota_obj = server_resp.object
           return (server_resp.status == 200, quota_obj)
       except Exception, e:
           logger.exception("Exception occured updating quota. Body:%s"
                            % body)
           return (False, None)


    def ex_update_quota_for_user(self, tenant_id, user_id, values, use_tenant_id=True):
       """
       Updates value/values in quota set
       @keyword tenant_id: Tenant or Project ID to update. Typically a UUID.
       @type    tenant_id: C{str}
       @keyword user_id: User ID to update. Typically a UUID.
       @type    user_id: C{str}
       @keyword values: A Dict containing the new key/value for quota set
       @type    values: C{dict}
       """
       if use_tenant_id:
           values['tenant_id'] = tenant_id
       body = {'quota_set': values}
       server_resp = self.connection.request('/os-quota-sets/%s?user_id=%s'
                                             % (tenant_id, user_id),
                                             method='PUT',
                                             data=body)
       try:
           quota_obj = server_resp.object
           return (server_resp.status == 200, quota_obj)
       except BaseHTTPError, e:
           if 'Quota limit' in e.msg or 'must be less' in e.msg or 'must less' in e.msg:
               return self.ex_update_quota(self, tenant_id, values)
       except Exception, e:
           logger.exception("Exception occured updating quota. Body:%s"
                            % body)
           return (False, None)

