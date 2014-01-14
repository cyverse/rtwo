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


from threepio import logger

from rtwo.drivers.common import _connect_to_neutron,\
    get_default_subnet
from neutronclient.common.exceptions import NeutronClientException

class NetworkManager(object):

    neutron = None
    default_router = None

    def __init__(self, *args, **kwargs):
        self.default_router = kwargs.get('router_name')
        self.neutron = self.new_connection(*args, **kwargs)

    def new_connection(self, *args, **kwargs):
        """
        Allows us to make another connection (As the user)
        """
        neutron = _connect_to_neutron(*args, **kwargs)
        return neutron

    ##Admin-specific methods##
    def project_network_map(self):
        named_subnets = self.find_subnet('-subnet', contains=True)
        users_with_networks = [net['name'].replace('-subnet', '')
                               for net in named_subnets]
        user_map = {}
        for user in users_with_networks:
            my_network = self.find_network('%s-net' % user)[0]
            my_subnet = self.find_subnet('%s-subnet' % user)[0]
            my_router_interface = self.find_router_interface(
                self.default_router,
                '%s-subnet' % user)
            user_map[user] = {'network': my_network,
                              'subnet': my_subnet,
                              'public_interface': my_router_interface}
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

    def create_project_network(self, username, password,
                               project_name, get_unique_number=None, **kwargs):
        """
        This method should be run once when a new project is created
        (As the user):
        Create a network, subnet, and router
        Add interface between router and network
        (As admin):
        Add interface between router and gateway
        """

        auth_url = kwargs.get('auth_url')
        region_name = kwargs.get('region_name')
        router_name = kwargs.get('router_name')
        # Step 1. Does public router exist?
        public_router = self.find_router(router_name)
        if public_router:
            public_router = public_router[0]
        else:
            raise Exception("Default public router was not found.")
        # Step 2. Set up user-specific virtual network
        user_neutron = self.get_user_neutron(username, password, project_name,
                                             auth_url, region_name)
        network = self.create_network(user_neutron, '%s-net' % project_name)
        subnet = self.create_user_subnet(user_neutron,
                                         '%s-subnet' % project_name,
                                         network['id'],
                                         username,
                                         get_unique_number=get_unique_number,
                                         get_cidr=get_default_subnet)
        #self.create_router(user_neutron, '%s-router' % project_name)
        self.add_router_interface(public_router,
                                  subnet,
                                  '%s-router-intf' % project_name)
        #self.set_router_gateway(user_neutron, '%s-router' % project_name)
        return (network, subnet)

    def delete_project_network(self, username, project_name):
        """
        remove_interface_router
        delete_subnet
        delete_network
        """
        self.remove_router_interface(self.neutron,
                                     self.default_router,
                                     '%s-subnet' % project_name)
        self.delete_subnet(self.neutron, '%s-subnet' % project_name)
        self.delete_network(self.neutron, '%s-net' % project_name)

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

    def associate_floating_ip(self, server_id):
        """
        Create a floating IP on the external network
        Find port of new VM
        Associate new floating IP with the port assigned to the new VM
        """
        #TODO: Look at the network if it already has a floating ip, dont
        #re-create
        external_networks = [net for net
                             in self.lc_list_networks()
                             if net.extra['router:external']]
        body = {'floatingip':
                {'floating_network_id': external_networks[0].id}}
        new_ip = self.neutron.create_floatingip(body)['floatingip']

        instance_ports = self.list_ports(device_id=server_id)
        body = {'floatingip':
                {'port_id': instance_ports[0]['id']}}
        updated_ip = self.neutron.update_floatingip(new_ip['id'],
                                                     body)
        logger.info('updated_floatingip - %s:%s' % (server_id, updated_ip))
        assigned_ip = updated_ip['floatingip']
        logger.info('Assigned Floating IP - %s:%s' % (server_id, assigned_ip))
        return assigned_ip

    def create_port(self, server_id, network_id, name=None):
        """
        Create a new (Fixed IP) Port between server id and the user network
        """
        if not name:
            name = 'fixed_ip_%s' % (server_id,)
        port_obj = self.neutron.create_port(
                {'port': 
                    {
                        'network_id':network_id,
                        'device_id':server_id,
                        'admin_state_up':True,
                        'name':name
                    }
                })
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

    def rename_security_group(self, project):
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
            sec_group = self.neutron.update_security_group(
                    default_group_id, 
                    {"security_group": {"description": project.name}})
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

    def lc_list_networks(self):
        """
        Call neutron list networks and convert to libcloud objects
        """
        network_list = self.neutron.list_networks()
        return [self._to_lc_network(net) for net in network_list['networks']]

    def _to_lc_network(self, net):
        from libcloud.compute.drivers.openstack import OpenStackNetwork
        return OpenStackNetwork(id=net['id'],
                                name=net['name'],
                                cidr=net.get('cidr', None),
                                extra=net,
                                driver=self)

    ##LOOKUP##
    def find_network(self, network_name, contains=False):
        return [net for net in self.neutron.list_networks()['networks']
                if network_name == net['name']
                or (contains and network_name in net['name'])]

    def find_subnet(self, subnet_name, contains=False):
        return [net for net in self.neutron.list_subnets()['subnets']
                if subnet_name == net['name']
                or (contains and subnet_name in net['name'])]

    def find_router(self, router_name):
        return [net for net in self.neutron.list_routers()['routers']
                if router_name == net['name']]

    def get_port(self, port_id):
        ports = self.list_ports()
        if not ports:
            return []
        for port in ports:
            if port['id'] == port_id:
                return port
        return None

    def find_ports(self, router_name):
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
        router_ports = self.find_ports(router_name)
        router_interfaces = []
        for port in router_ports:
            if 'router_interface' not in port['device_owner']:
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

    def create_user_subnet(self, neutron, subnet_name,
                           network_id, username,
                           ip_version=4, get_unique_number=None,
                           get_cidr=get_default_subnet):
        """
        Create a subnet for the user using the get_cidr function to get
        a private subnet range.
        """
        success = False
        inc = 0
        MAX_SUBNET = 4064
        cidr = None
        while not success and inc < MAX_SUBNET:
            try:
                cidr = get_cidr(username, inc, get_unique_number)
                if cidr:
                    return self.create_subnet(neutron, subnet_name,
                                              network_id, ip_version,
                                              cidr)
                else:
                    logger.warn("Unable to create cidr for subnet "
                                "for user: %s" % username)
                    inc += 1
            except Exception as e:
                logger.exception(e)
                logger.warn("Unable to create subnet for user: %s" % username)
                if not get_unique_number:
                    logger.warn("No get_unique_number method "
                                "provided for user: %s" % username)
                inc += 1
        if not success or not cidr:
            raise Exception("Unable to create subnet for user: %s" % username)

    def create_subnet(self, neutron, subnet_name,
                      network_id, ip_version=4, cidr='172.16.1.0/24'):
        existing_subnets = self.find_subnet(subnet_name)
        if existing_subnets:
            logger.info('Subnet %s already exists' % subnet_name)
            return existing_subnets[0]
        subnet = {
            'name': subnet_name,
            'network_id': network_id,
            'ip_version': ip_version,
            'cidr': cidr,
            'dns_nameservers':[
                '128.196.11.233',
                '128.196.11.234',
                '128.196.11.235',
                ]} #['8.8.8.8', '8.8.4.4']}
        logger.debug(subnet)
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
        router_id = self.get_router_id(neutron, router_name)
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
        router_id = self.get_router_id(neutron, router_name)
        subnet_id = self.get_subnet_id(neutron, subnet_name)
        #TODO: Devote some time to ensuring the interface router exists BEFORE
        #making a call to remove it
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
        router_id = self.get_router_id(neutron, router_name)
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
