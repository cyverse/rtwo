"""
OpenStack Network Admin Libarary

    Create:
    # To create a libcloud driver use the lc_driver_init method.
    # For instance with an rtwo OpenStack driver it's driver._connection.
    nm = NetworkManager.lc_driver_init(driver._connection)

    Use this library to:
      * manage networks within Neutron - openstack networking
"""
import os
import netaddr


from threepio import logger

from rtwo.drivers.common import _connect_to_heat, _connect_to_sahara, _connect_to_neutron, _connect_to_keystone_v3
from neutronclient.common.exceptions import NeutronClientException, NotFound

ROUTER_INTERFACE_NAMESPACE = (
    'network:router_interface',
    'network:router_interface_distributed',
    'network:ha_router_replicated_interface'
)

class NetworkManager(object):

    neutron = None
    default_router = None

    def __init__(self, *args, **kwargs):
        self.default_router = kwargs.pop("router_name", None)
        self.neutron, self.sahara, self.heat  = self.new_connection(*args, **kwargs)

    def new_connection(self, *args, **kwargs):
        """
        Allows us to make another connection (As the user)
        """
        #NOTE: This is a HACK that should be removed when we stop supporting "Legacy Openstack"
        if 'auth_url' in kwargs and '/v2' in kwargs['auth_url']:
            neutron = _connect_to_neutron(*args, **kwargs)
            sahara = None
            heat = None
        elif 'session' not in kwargs:
            if 'project_name' not in kwargs and 'tenant_name' in kwargs:
                kwargs['project_name'] = kwargs['tenant_name']
            (auth, session, token) = _connect_to_keystone_v3(**kwargs)
            neutron = _connect_to_neutron(session=session)
            sahara = _connect_to_sahara(session=session)
            heat = _connect_to_heat(session=session)
        else:
            neutron = _connect_to_neutron(*args, **kwargs)
            sahara = _connect_to_sahara(*args, **kwargs)
            heat = _connect_to_heat(*args, **kwargs)
        return neutron, sahara, heat

    def tenant_networks(self, tenant_id=None):
        if not tenant_id:
            tenant_id = self.get_tenant_id()
        tenant_nets = self.list_networks(tenant_id=tenant_id)
        return tenant_nets

    def get_tenant_id(self):
        credentials = self.get_credentials()
        try:
            tenant_id = credentials.get('auth_tenant_id')
            return tenant_id
        except KeyError:
            logger.warn(
                "Key 'auth_tenant_id' no longer exists in"
                "'get_credentials()'")
            return None

    def get_credentials(self):
        """
        Return the user_id and tenant_id of the network manager
        """
        auth_info = self.neutron.httpclient.get_auth_info()
        if not auth_info.get('auth_tenant_id'):
            self.list_networks()
            auth_info = self.neutron.httpclient.get_auth_info()
        auth_info.pop('auth_token')
        return auth_info

    ##Admin-specific methods##
    def project_network_map(self):
        named_networks = self.find_network('-net', contains=True)
        users_with_networks = [net['name'].replace('-net', '')
                               for net in named_networks]
        user_map = {}
        networks = self.list_networks()
        subnets = self.list_subnets()
        routers = self.list_routers()
        ports = self.list_ports()
        for user in users_with_networks:
            my_nets = [net for net in networks if '%s-net' % user in net['name']]
            net_ids = [n['id'] for n in my_nets]
            my_subnets = [subnet for subnet in subnets if '%s-subnet' % user in subnet['name']]
            subnet_ids = [s['id'] for s in my_subnets]
            my_ports = []
            for port in ports:
                if 'dhcp' in port['device_owner'] or \
                        'compute:None' in port['device_owner']:
                    #Skip these ports..
                    continue
                if port['network_id'] in net_ids:
                    my_ports.append(port)
                    continue
                fixed_ips = port['fixed_ips']
                for fixed_ip in fixed_ips:
                    if fixed_ip['subnet_id'] in subnet_ids:
                        my_ports.append(port)
                        break
            #TODO: Can you have more than one of these?
            if len(my_nets) == 1:
                my_nets = my_nets[0]
            if len(my_subnets) == 1:
                my_subnets = my_subnets[0]
            user_map[user] = {'network': my_nets,
                              'subnet': my_subnets,
                              'public_interface': my_ports}
            logger.debug("Added user %s" % user_map[user])
        return user_map

    def get_user_neutron(self, username, password,
                         project_name, auth_url, region_name):
        user_creds = {
            'username': username,
            'password': password,
            'tenant_name': project_name,
            'auth_url': auth_url,
            'region_name': region_name
        }
        user_neutron = self.new_connection(**user_creds)
        return user_neutron

    def disassociate_floating_ip(self, server_id):
        """
        Remove floating IP from the server <server_id>
        * NO return value
        * raises NeutronClientException if delete fails
        """
        floating_ip_id = None
        for f_ip in self.list_floating_ips():
            if f_ip.get('instance_id') == server_id:
                floating_ip_id = f_ip['id']
        #No floating ip matches - Disassociate has nothing to do
        if not floating_ip_id:
            return
        #Remove floating ip
        deleted_ip = self.neutron.delete_floatingip(floating_ip_id)
        return

    def associate_floating_ip(self, server_id, external_network_id=None):
        """
        Create a floating IP on the external network
        Find port of new VM
        Associate new floating IP with the port assigned to the new VM
        If external_network_id is not specified then an external network is
        chosen arbitrarily. This may not work if there are multiple external
        networks.
        """
        networks = self.list_networks()
        if external_network_id is None:
            external_networks = [net for net in networks
                                 if net['router:external']]
            if not external_networks:
                raise Exception("CONFIGURATION ERROR! No external networks"
                                " found! Cannot associate floating ip without"
                                " it! Create a fixed IP/port first!")
            external_network_id = external_networks[0]['id']

        instance_ports = self.list_ports(device_id=server_id)
        if not instance_ports:
            raise Exception("No ports found with device_id == %s."
                            " Create a fixed IP/port first!" % server_id)
        #TODO: Look at the network if it already has a floating ip, dont
        #re-create
        body = {'floatingip': {
                   'port_id': instance_ports[0]['id'],
                   'floating_network_id': external_network_id
               }}
        new_ip = self.neutron.create_floatingip(body)['floatingip']

        logger.info('Assigned Floating IP - %s:%s' % (server_id, new_ip))
        return new_ip

    def create_port(self, server_id, network_id, subnet_id=None,
            ip_address=None, tenant_id=None, mac_address=None, name=None):
        """
        Create a new (Fixed IP) Port between server id and the user network
        """
        if not name:
            name = 'fixed_ip_%s' % (server_id,)
        port_data = {'port':
                {
                    "tenant_id": tenant_id,
                    "network_id":network_id,
                    "device_id":server_id,
                    "fixed_ips": [{"subnet_id":subnet_id, "ip_address":
                        ip_address}],
                    'admin_state_up':True,
                    'name':name
                }
            }
        if mac_address:
            port_data['port']['mac_address'] = mac_address
        if subnet_id and ip_address:
            #In this case, we should attach the interface after the fact.
            port_data['port'].pop('device_id')
        port_obj = self.neutron.create_port(port_data)
        return port_obj['port']


    def find_server_ports(self, server_id):
        """
        Find all the ports for a given server_id (device_id in port object).
        """
        server_ports = []
        all_ports = self.list_ports()
        return [p for p in all_ports if p['device_id'] == server_id]

    def list_floating_ips(self):
        instance_ports = self.list_ports()
        floating_ips = self.neutron.list_floatingips()['floatingips']
        # Connect instances and floating_ips using ports.
        for fip in floating_ips:
            port = filter(lambda(p): p['id'] == fip['port_id'], instance_ports)
            if port:
                fip['instance_id'] = port[0]['device_id']
        #logger.debug(floating_ips)
        return floating_ips

    def rename_security_group(self, project, security_group_name=None):
        security_group_resp = self.neutron.list_security_groups(
                tenant_id=project.id)
        default_group_id = None
        for sec_group in security_group_resp['security_groups']:
            if 'default' in sec_group['name']:
                default_group_id = sec_group['id']
                break
        if not default_group_id:
            raise Exception("Could not find the security group named 'default'")
        try:
            if not security_group_name:
                security_group_name = project.name
            #FIXME: we don't actually name it?
            sec_group = self.neutron.update_security_group(
                    default_group_id,
                    {"security_group": {"description": security_group_name}})
            return sec_group
        except NeutronClientException:
            logger.exception("Problem updating description of 'default'"
                             "security group to %s" % project.name)
            raise


    ##Libcloud-Neutron Interface##
    @classmethod
    def lc_driver_init(self, lc_driver, *args, **kwargs):
        lc_driver_args = {
            'username': lc_driver.key,
            'password': lc_driver.secret,
            'tenant_name': lc_driver._ex_tenant_name,
            #Libcloud requires /v2.0/tokens -- OS clients do not.
            'auth_url': lc_driver._ex_force_auth_url.replace('/tokens',''),
            'region_name': lc_driver._ex_force_service_region}
        lc_driver_args.update(kwargs)
        manager = NetworkManager(*args, **lc_driver_args)
        return manager

    def lc_list_networks(self, *args, **kwargs):
        """
        Call neutron list networks and convert to libcloud objects
        """
        network_list = self.neutron.list_networks(*args, **kwargs)
        return [self._to_lc_network(net) for net in network_list['networks']]

    def _to_lc_network(self, net):
        from libcloud.compute.drivers.openstack import OpenStackNetwork
        return OpenStackNetwork(id=net['id'],
                                name=net['name'],
                                cidr=net.get('cidr', None),
                                extra=net,
                                driver=self)
    ##GET##
    def get_network(self, network_id):
        for net in self.neutron.list_networks()['networks']:
            if network_id == net['id']:
                return net
        return None

    def get_subnet(self, subnet_id):
        for subnet in self.neutron.list_subnets()['subnets']:
            if subnet_id == subnet['id']:
                return subnet
        return None

    def get_port(self, port_id):
        ports = self.list_ports()
        if not ports:
            return []
        for port in ports:
            if port['id'] == port_id:
                return port
        return None
    ##Easy Lists##
    def list_networks(self, *args, **kwargs):
        """
        NOTE: kwargs can be: tenant_id=, or any other attr listed in the
        details of a network.
        """
        return self.neutron.list_networks(*args, **kwargs)['networks']

    def list_subnets(self):
        return self.neutron.list_subnets()['subnets']

    def list_routers(self):
        return self.neutron.list_routers()['routers']

    ##LOOKUP##
    def find_tenant_resources(self, tenant_id, instance_ids=[]):
        networks = [net for net in self.list_networks()
                    if net['tenant_id'] == tenant_id]
        ports = [port for port in self.list_ports()
                 if port['tenant_id'] == tenant_id
                 or port['device_id'] in instance_ids]
        subnets = [subnet for subnet in self.list_subnets()
                    if subnet['tenant_id'] == tenant_id]
        routers = [router for router in self.list_routers()
                    if router['tenant_id'] == tenant_id]
        return {"ports": ports,
                "networks": networks,
                "subnets": subnets,
                "routers": routers
               }
    def find_network(self, network_name, contains=False):
        return [net for net in self.list_networks()
                if network_name == net['name']
                or (contains and network_name in net['name'])]

    def find_subnet(self, subnet_name, contains=False):
        return [net for net in self.list_subnets()
                if subnet_name == net['name']
                or (contains and subnet_name in net['name'])]

    def find_router(self, router_name):
        return [net for net in self.list_routers()
                if router_name == net['name']]

    def find_ports_for_router(self, router_name):
        routers = self.find_router(router_name)
        if not routers:
            return []
        router_id = routers[0]['id']
        return [port for port in self.list_ports()
                if router_id == port['device_id']]

    def list_ports(self, **kwargs):
        """
        Options:
        subnet_id=subnet.id
        device_id=device.id
        ip_address=111.222.333.444
        """
        return self.neutron.list_ports(**kwargs)['ports']

    def find_router_interface(self, router, subnet):
        #If no router/subnet, return None
        if not router or not subnet:
            return None
        #If str router/subnet, find the obj
        if type(router) != dict:
            routers = self.find_router(router)
            if not routers:
                logger.info('Router %s does not exists' % router)
                return None
            router = routers[0]

        if type(subnet) != dict:
            subnets = self.find_subnet(subnet)
            if not subnets:
                logger.info('Subnet %s does not exists' % subnet)
                return None
            subnet = subnets[0]

        #Return the router interfaces matching router+subnet
        router_name = router['name']
        subnet_id = subnet['id']
        router_ports = self.find_ports_for_router(router_name)
        router_interfaces = []
        for port in router_ports:
            if port['device_owner'] not in ROUTER_INTERFACE_NAMESPACE:
                continue
            subnet_match = False
            for ip_subnet_obj in port['fixed_ips']:
                if subnet_id in ip_subnet_obj['subnet_id']:
                    subnet_match = True
                    break
            if subnet_match:
                router_interfaces.append(port)
        return router_interfaces

    def find_router_gateway(self,
                            router_name,
                            external_network_name='ext_net'):
        network_id = self.find_network(external_network_name)[0]['id']
        routers = self.find_router(router_name)
        if not routers:
            return
        return [r for r in routers if r.get('external_gateway_info') and
                network_id in r['external_gateway_info'].get('network_id', '')]

    ##ADD##
    def create_network(self, neutron, network_name):
        existing_networks = self.find_network(network_name)
        if existing_networks:
            logger.info('Network %s already exists' % network_name)
            return existing_networks[0]

        network = {'name': network_name, 'admin_state_up': True}
        network_obj = neutron.create_network({'network': network})
        return network_obj['network']


    def validate_cidr(self, cidr):
        logger.info("Attempting to validate cidr %s" % cidr)
        test_cidr_set = netaddr.IPSet([cidr])
        all_subnets = [subnet for subnet in self.list_subnets()
                       if subnet.get('ip_version', 4) != 6]
        all_subnet_ips = [sn['allocation_pools'] for sn in all_subnets]
        for idx, subnet_ip_list in enumerate(all_subnet_ips):
            for subnet_ip_range in subnet_ip_list:
                (start, end) = (subnet_ip_range['start'], subnet_ip_range['end'])
                if start.startswith('10') or end.startswith('10') or start.startswith('192') or end.startswith('192'):
                    continue
                test_range = netaddr.IPRange(
                    subnet_ip_range['start'], subnet_ip_range['end'])
                if len(test_range) > 1000:
                    continue
                for ip in test_range:
                    if ip in test_cidr_set:
                        raise Exception("Overlap detected for CIDR %s and Subnet %s" % (cidr, all_subnets[idx]))
        return True

    def create_subnet(self, neutron, subnet_name,
                      network_id, ip_version=4, cidr=None,
                      dns_nameservers=[], subnet_pool_id=None):
        existing_subnets = self.find_subnet(subnet_name)
        if existing_subnets:
            logger.info('Subnet %s already exists' % subnet_name)
            return existing_subnets[0]
        #self.validate_cidr(cidr)
        subnet = {
            'name': subnet_name,
            'network_id': network_id,
            'ip_version': ip_version,
        }
        if subnet_pool_id:
            subnet['subnetpool_id'] = subnet_pool_id
        else:
            if not dns_nameservers:
                dns_nameservers = ['8.8.8.8', '8.8.4.4']
            subnet['dns_nameservers'] = dns_nameservers
            subnet['cidr'] = cidr
        logger.debug("Creating subnet - %s" % subnet)
        subnet_obj = neutron.create_subnet({'subnet': subnet})
        return subnet_obj['subnet']

    def create_router(self, neutron, router_name):
        existing_routers = self.find_router(router_name)
        if existing_routers:
            logger.info('Router %s already exists' % router_name)
            return existing_routers[0]
        router = {'name': router_name, 'admin_state_up': True}
        router_obj = neutron.create_router({'router': router})
        return router_obj['router']

    def add_router_interface(self, router, subnet, interface_name=None):
        existing_router_interfaces = self.find_router_interface(router, subnet)
        if existing_router_interfaces:
            logger.info('Router Interface for Subnet:%s-Router:%s already'
                        'exists' % (subnet['name'], router['name']))
            return existing_router_interfaces[0]
        body = {"subnet_id": subnet['id']}
        interface_obj = self.neutron.add_interface_router(router['id'], body)
        if interface_name:
            self.neutron.update_port(
                    interface_obj['port_id'],
                    {"port":{"name":interface_name}})
        return interface_obj

    def set_router_gateway(self, neutron, router_name,
                           external_network_name='ext_net'):
        """
        Must be run as admin
        """
        existing_gateways = self.find_router_gateway(router_name,
                                                     external_network_name)
        if existing_gateways:
            logger.info('Router gateway for External Network:%s-Router:%s\
                already exists' % (external_network_name, router_name))
            return existing_gateways[0]
        #Establish the router_gateway
        router_id = self.get_router_id(self.neutron, router_name)
        external_network = self.get_network_id(neutron, external_network_name)
        body = {'network_id': external_network}
        return self.neutron.add_gateway_router(router_id, body)

    ## LOOKUPS##
    def get_subnet_id(self, neutron, subnet_name):
        sn_list = neutron.list_subnets(name=subnet_name)
        if sn_list and sn_list.get('subnets'):
            return sn_list['subnets'][0]['id']

    def get_router_id(self, neutron, router_name):
        rt_list = neutron.list_routers(name=router_name)
        if rt_list and rt_list.get('routers'):
            return rt_list['routers'][0]['id']

    def get_network_id(self, neutron, network_name):
        nw_list = neutron.list_networks(name=network_name)
        if nw_list and nw_list.get('networks'):
            return nw_list['networks'][0]['id']

    ##DELETE##
    def remove_router_gateway(self, router_name):
        router_id = self.get_router_id(self.neutron, router_name)
        if router_id:
            return self.neutron.remove_gateway_router(router_id)

    def remove_router_interface(self, neutron, router_name, subnet_name):
        router_id = self.get_router_id(self.neutron, router_name)
        subnet_id = self.get_subnet_id(neutron, subnet_name)
        #FIXME: Ensure no instances/IPs are using the interface
        # && raise an error if they try!
        if router_id and subnet_id:
            try:
                return neutron\
                    .remove_interface_router(router_id,
                                             {"subnet_id": subnet_id})
            except NeutronClientException, neutron_err:
                if 'no interface on subnet' in neutron_err:
                    #Attempted to delete a connection that does not exist.
                    #Ignore this conflict.
                    return
                logger.exception("Problem deleting interface router"
                             " from router %s to subnet %s."
                             % (router_id, subnet_id))
                raise

    def delete_router(self, neutron, router_name):
        router_id = self.get_router_id(self.neutron, router_name)
        if router_id:
            try:
                return neutron.delete_router(router_id)
            except:
                logger.error("Problem deleting router: %s" % router_id)
                raise

    def delete_subnet(self, neutron, subnet_name):
        subnet_id = self.get_subnet_id(neutron, subnet_name)
        if subnet_id:
            try:
                return neutron.delete_subnet(subnet_id)
            except:
                logger.error("Problem deleting subnet: %s" % subnet_id)
                raise

    def delete_network(self, neutron, network_name):
        network_id = self.get_network_id(neutron, network_name)
        if network_id:
            try:
                return neutron.delete_network(network_id)
            except:
                logger.error("Problem deleting network: %s" % network_id)
                raise

    def delete_port(self, port):
        return self.neutron.delete_port(port['id'])
