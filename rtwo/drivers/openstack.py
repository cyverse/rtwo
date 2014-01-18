"""
Extension of libcloud's OpenStack Node Driver.
"""
import binascii
import copy
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
from libcloud.compute.base import StorageVolume,\
    NODE_ONLINE_WAIT_TIMEOUT, SSH_CONNECT_TIMEOUT,\
    NodeAuthPassword, NodeDriver
from libcloud.compute.drivers.openstack import OpenStack_1_1_NodeDriver
from libcloud.utils.py3 import httplib

from neutronclient.common.exceptions import NeutronClientException

from rfive.fabricSSH import FabricSSHClient

from rtwo.drivers.openstack_network import NetworkManager


class OpenStack_Esh_NodeDriver(OpenStack_1_1_NodeDriver):
    """
    OpenStack node driver for esh.
    """

    features = {
        "_to_volume": ["Convert native object to StorageVolume"],
        "_to_size": ["Add cpu info to extra, duplicate of vcpu"],
        "_to_image": ["Add state info to extra"],
        "_to_node": ["Build public_ips field",
                     "public_ips as extra",
                     "keypairs as extra",
                     "user/tenant as extra"],
        "create_node": ["Create node with ssh_key", "ssh_key"],
        "ex_create_node_with_network": ["Create node with floating IP"
                                        " and ssh_key", "ssh_key"],
        "ex_deploy_to_node": ["Deploy to existing node"],
        "ex_suspend_node": ["Suspends the node"],
        "ex_resume_node": ["Resume the node"],
        "ex_start_node": ["Starts the node"],
        "ex_stop_node": ["Stops the node"],
        "create_volume": ["Create volume"],
        "delete_volume": ["Delete volume"],
        "list_volumes": ["List all volumes"],
        "update_volume": ["Updates name and metadata on the volume"],
        "attach_volume": ["Attach volume to node"],
        "detach_volume": ["Detach volume from node"],
        "destroy_volume": ["Delete volume"],
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
    }

    """
    Object builders -- Convert the native dict in to a Libcloud object
    """
    def _to_volumes(self, el, glance=False):
        return [self._to_volume(volume, glance=glance) for volume in el['volumes']]

    def _to_volume(self, api_volume, glance=False):
        if glance:
            created_at = api_volume['created_at']
            display_name = api_volume['display_name']
            display_description = api_volume['display_description']
            availability_zone = api_volume['availability_zone']
            snapshot_id = api_volume['snapshot_id']
            attachmentSet = api_volume['attachments']
            for attachment in attachmentSet:
                attachment['serverId'] = attachment.pop('server_id')
                attachment['volumeId'] = attachment.pop('volume_id')
        else:
            created_at = api_volume['createdAt']
            display_name = api_volume['displayName']
            display_description = api_volume['displayDescription']
            availability_zone = api_volume['availabilityZone']
            snapshot_id = api_volume['snapshotId']
            attachmentSet = api_volume['attachments']

        created_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%f')
        extra = {
            'id': api_volume['id'],
            'displayName': display_name,
            'displayDescription': display_description,
            'size': api_volume['size'],
            'status': api_volume['status'],
            'metadata': api_volume['metadata'],
            'availabilityZone': availability_zone,
            'snapshotId': snapshot_id,
            'attachmentSet': attachmentSet,
            'createTime': created_time,
        }
        return StorageVolume(id=api_volume['id'],
                             name=display_name,
                             size=api_volume['size'],
                             driver=self,
                             extra=extra)

    def _to_size(self, api_size):
        """
        Extends Openstack_1_1_NodeDriver._to_size,
        adds support for cpu
        """
        size = super(OpenStack_Esh_NodeDriver, self)._to_size(api_size)
        size._api = api_size
        size.extra = {
                'cpu': api_size['vcpus'],
                'ephemeral': api_size.get('OS-FLV-EXT-DATA:ephemeral',0),
                'public': api_size.get('os-flavor-access:is_public',True)
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
        return image

    def neutron_set_ips(self, node, floating_ips):
        """
        Using the network manager, find all IPs associated with this node
        """
        for f_ip in floating_ips:
            if f_ip.get('instance_id') == node.id:
                node.public_ips.append(f_ip['floating_ip_address'])
        return

    def _to_nodes(self, el):
        network_manager = NetworkManager.lc_driver_init(self)
        floating_ip_list = network_manager.list_floating_ips()
        return [self._to_node(
                    api_node, floating_ips=floating_ip_list) 
                    for api_node in el['servers']]

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
            'task': api_node.get('OS-EXT-STS:task_state'),
            'power': api_node.get('OS-EXT-STS:power_state'),
            'object': api_node
        })
        return node

    def create_node(self, **kwargs):
        """
        Helpful arguments to set:
        ex_keyname : Name of existing public key
        """
        node = super(OpenStack_Esh_NodeDriver, self).create_node(**kwargs)

        #NOTE: This line is needed to authenticate via SSH_Keypair instead!
        node.extra['password'] = None

        return node

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
                    task=kwargs['deploy'], node=node,
                    ssh_hostname=ip_addresses[0], ssh_port=ssh_port,
                    ssh_username=username, ssh_password=password,
                    ssh_key_file=ssh_key_file, ssh_timeout=ssh_timeout,
                    timeout=timeout, max_tries=max_tries)
            except Exception as exc:
                # Try alternate username
                # Todo: Need to fix paramiko so we can catch a more specific
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
                ssh_client.close()
                return node

    def ex_list_networks(self, region=None):
        """
        Overrides the 'os-networksv2' API from libcloud in favor of the
        Openstack Network Manager. We will use this until libcloud completely
        supports neutron
        """
        from atmosphere import settings
        network_manager = NetworkManager(**settings.OPENSTACK_ARGS)
        return network_manager.lc_list_networks()

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

    def ex_suspend_node(self, node):
        """
        Suspend a node.
        """
        resp = self._node_action(node, 'suspend')
        return resp.status == httplib.ACCEPTED

    def ex_resume_node(self, node):
        """
        Resume a node.
        """
        resp = self._node_action(node, 'resume')
        return resp.status == httplib.ACCEPTED

    #quotas
    def _establish_connection(self):
        """
        This function will contact keystone for authorization
        and make an empty request to the server.

        Doing this will provide self.connection.auth_user_info.
        """
        try:
            self.connection.request('')
        except:
            #Will fail,but we MUST make a request to authenticate
            pass

    def _get_user_id(self):
        if not self.connection.auth_user_info:
            self._establish_connection()
        return self.connection.auth_user_info.get('id')

    def _get_tenant_id(self):
        if not self.connection.request_path:
            self._establish_connection()
        tenant_id = self.connection.request_path.split('/')[-1]
        return tenant_id

    def ex_get_quota(self):
        tenant_id = self._get_tenant_id()
        return self.connection.request("/os-quota-sets/%s" % tenant_id).object

    def ex_update_quota_for_user(self, tenant_id, user_id, values):
        """
        Updates value/values in quota set

        @keyword tenant_id: Tenant or Project ID to update. Typically a UUID.
        @type    tenant_id: C{str}

        @keyword user_id: User ID to update. Typically a UUID.
        @type    user_id: C{str}

        @keyword values: A Dict containing the new key/value for quota set
        @type    values: C{dict}
        """
        values['tenant_id'] = tenant_id
        body = {'quota_set': values}
        server_resp = self.connection.request('/os-quota-sets/%s?user_id=%s'
                                              % (tenant_id, user_id),
                                              method='PUT',
                                              data=body)
        try:
            quota_obj = server_resp.object
            return (server_resp.status == 200, quota_obj)
        except Exception, e:
            logger.exception("Exception occured updating quota. Body:%s"
                             % body)
            return (False, None)

    #Volumes
    def create_volume(self, **kwargs):
        """
        Create a new volume

        @keyword name: The name of the new volume
        @type    name: C{str}

        @keyword description: A description for the new volume (Optional)
        @type    description: C{str}

        @keyword size: The size of the new volume
        @type    size: C{int}
        """
        body = {'volume': {
            'display_name': kwargs.get('name', ''),
            'display_description': kwargs.get('description', ''),
            'size': kwargs.get('size', '1')
        }
        }
        server_resp = self.connection.request('/os-volumes',
                                              method='POST',
                                              data=body)
        try:
            volume_obj = self._to_volume(server_resp.object['volume'])
            return (server_resp.status == 200, volume_obj)
        except Exception, e:
            logger.exception("Exception occured creating volume")
            return (False, None)

    def list_volumes(self):
        return self._to_volumes(self.connection.request("/os-volumes").object)

    def update_volume(self, **kwargs):
        """
        """
        data_dict = {'volume': {}}
        #Add information to be updated
        if kwargs.get('display_name', None):
            data_dict['volume']['display_name'] = kwargs['display_name']
        if kwargs.get('display_description', None):
            data_dict['volume']['display_description'] =\
                kwargs['display_description']
        if kwargs.get('metadata', None):
            data_dict['volume']['metadata'] = kwargs['metadata']
        server_resp = self.connection.request('/os-volumes/%s' % kwargs['id'],
                                              method='POST',
                                              data=data_dict)
        try:
            return (server_resp.status == 200, server_resp.object['volume'])
        except Exception, e:
            logger.exception("Exception occured updating volume")
            return (False, None)

    #Volume Attachment
    def attach_volume(self, node, volume, device=None):
        """
        Attaches volume to node at device location
        """
        server_id = node.id
        volume_id = volume.id
        server_resp = self.connection.request(
            '/servers/%s/os-volume_attachments' % server_id,
            method='POST',
            data={'volumeAttachment':
                 {'volumeId': volume_id,
                  'device': device
                  }
                  })
        return server_resp

    def detach_volume(self, volume):
        """
        Detaches volume from a node
        """
        server_id = volume.attachment_set[0].get('serverId')
        volume_id = volume.id
        server_resp = self.connection.request(
            '/servers/%s/os-volume_attachments/%s' %
            (server_id, volume_id),
            method='DELETE')
        return server_resp.status == 202

    def destroy_volume(self, volume):
        """
        Destroys a single volume
        """
        volume_id = volume.id
        server_resp = self.connection.request(
            '/os-volumes/%s' % (volume_id,),
            method='DELETE')
        return server_resp.status == 202

    def ex_list_all_instances(self):
        """
        List all instances from all tenants of a user
        """
        server_resp = self.connection.request(
            '/servers/detail?all_tenants=1',
            method='GET')
        return self._to_nodes(server_resp.object)

    def ex_list_all_volumes(self):
        """
        List all volumes from all tenants of a user
        """
        lc_conn = self.connection
        if not lc_conn.service_catalog:
            lc_conn.get_service_catalog()
        #Change base_url, make request, update base_url
        if lc_conn._ex_force_base_url:
            old_endpoint = lc_conn._ex_force_base_url 
        else:
            old_endpoint = lc_conn.get_endpoint()
        try:
            new_service = lc_conn.service_catalog.get_endpoint(
                                service_type='volume',name='cinder',
                                region=lc_conn.service_region)
            lc_conn._ex_force_base_url = new_service['publicURL']
            server_resp = lc_conn.request(
                '/volumes/detail?all_tenants=1',
                method='GET')
            return self._to_volumes(server_resp.object, glance=True)
        finally:
            lc_conn._ex_force_base_url = old_endpoint


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

    def ex_hypervisor_statistics(self):
        return self.connection.request(
            "/os-hypervisors/statistics").object['hypervisor_statistics']

    #Floating IP Pool
    def ex_list_floating_ip_pools(self, **kwargs):
        """
        List all floating IP pools
        """
        def _to_ip_pools(ip_pool_list):
            return [ip_pool_obj for ip_pool_obj
                    in ip_pool_list['floating_ip_pools']]
        return _to_ip_pools(self.connection.request(
            "/os-floating-ip-pools").object)

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
        for f_ip in self.ex_list_floating_ips():
            if not f_ip.get('instance_id'):
                self.ex_deallocate_floating_ip(f_ip['id'])

    def ex_associate_floating_ip(self, server, address, **kwargs):
        """
        Associate an allocated floating IP to the node
        """
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server,
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
            server_resp = self.connection.request(
                '/servers/%s/action' % server.id,
                method='POST',
                data={'removeFloatingIp': {'address': address}})
            return server_resp.object
        except Exception, e:
            raise

    #Security Groups
    def ex_create_security_group(self, name,
                                 description='Created by Atmosphere--Libcloud',
                                 **kwargs):
        try:
            data = {
                'security_group': {
                    'name': name,
                    'description': description
                }
            }
            server_resp = self.connection.request(
                '/os-security-groups',
                method='POST',
                data=data)
            return server_resp.object
        except Exception, e:
            raise

    def ex_delete_security_group(self, sec_group_id, **kwargs):
        try:
            server_resp = self.connection.request(
                '/os-security-groups/%s' % sec_group_id,
                method='DELETE')
            return server_resp.object
        except Exception, e:
            raise

    def ex_list_security_groups(self, **kwargs):
        try:
            server_resp = self.connection.request(
                '/os-security-groups',
                method='GET')
            #PARSE _to_sec_groups & to_sec_group
            return server_resp.object
        except Exception, e:
            raise

    def ex_add_security_group(self, server, sec_group, **kwargs):
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server,
                method='POST',
                data={'addSecurityGroup': {'address': address}})
            return server_resp.object
        except Exception, e:
            raise

    def ex_remove_security_group(self, server, sec_group, **kwargs):
        try:
            server_resp = self.connection.request(
                '/servers/%s/action' % server,
                method='POST',
                data={'removeSecurityGroup': {'address': address}})
            return server_resp.object
        except Exception, e:
            raise

    #Security Group Rules
    def ex_create_security_group_rule(self, protocol, from_port,
                                      to_port, cidr, group_id,
                                      parent_group_id, **kwargs):
        try:
            server_resp = self.connection.request(
                '/os-security-group-rules',
                method='POST',
                data={"security_group_rule": {
                    "ip_protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                    "group_id": group_id,
                    "parent_group_id": parent_group_id}
                })
            return server_resp.object
        except Exception, e:
            raise

    def ex_delete_security_group_rule(self, sec_group_rule_id, **kwargs):
        try:
            server_resp = self.connection.request(
                '/os-security-group-rules/%s' % sec_group_rule_id,
                method='DELETE')
            return server_resp.object
        except Exception, e:
            raise

    def ex_list_security_group_rules(self, **kwargs):
        try:
            server_resp = self.connection.request(
                '/os-security-group-rules',
                method='GET')
            #PARSE _to_sec_group_rule & to_sec_group_rule
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

        #Can we assign a public ip? Node must be active
        if node.extra['status'] != 'active':
            raise Exception("Instance %s must be active before associating "
                            "floating IP" % node.id)

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

    def get_network_manager(self):
        return NetworkManager.lc_driver_init(self)

    def neutron_disassociate_ip(self, node, *args, **kwargs):
        """
        Remove IP (Neutron)
        There is no good way to interface libcloud + nova + neutron,
        instead we call neutronclient directly..
        Feel free to replace when a better mechanism comes along..
        """

        instance_id = node.id
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

    def _update_node(self, node, **node_updates):
        """
        OVERRIDES original implementation!
        This update will NOT replace all metadata on the server/node
        """
        return self.ex_set_metadata(node, node_updates, replace_metadata=False)

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
    def ex_set_metadata(self, node, metadata, replace_metadata=True):
        """
        Sets the Node's metadata.

        @param      image: Node
        @type       image: L{Node}

        @param      metadata: Key/Value metadata to associate with a node
        @type       metadata: C{dict}

        @param      replace_metadata: Replace all metadata on node with
        new metdata
        @type       replace_metadata: C{bool}

        @rtype: C{dict}
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
            '/servers/%s/metadata%s' % (node.id,'/%s' if key else ''),
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
