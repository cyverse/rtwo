"""
Atmosphere service meta.

DEPRECATION NOTE: This file should be removed. All relevant/useful work should be transferred out of this file.
"""
from abc import ABCMeta
from math import floor
import sys
import urlparse

from threepio import logger

from rtwo import settings

from rtwo.models.provider import AWSProvider, EucaProvider, OSProvider,\
    OSValhallaProvider
from rtwo.models.identity import AWSIdentity, EucaIdentity, OSIdentity
from rtwo.driver import AWSDriver, EucaDriver, OSDriver
from rtwo.linktest import active_instances

from rtwo.accounts.openstack import AccountDriver as OSAccountDriver


class BaseMeta(object):
    __metaclass__ = ABCMeta


class Meta(BaseMeta):

    provider = None

    metas = {}

    def __init__(self, driver, admin_driver=None):
        self._driver = driver._connection
        self.user = driver.identity.user
        self.provider = driver.provider
        self.provider_options = driver.provider.options
        self.identity = driver.identity
        self.driver = driver
        if not admin_driver:
            self.admin_driver = self.create_admin_driver({})
        else:
            self.admin_driver = admin_driver

    @classmethod
    def create_meta(cls, driver, admin_driver=None):
        meta = driver.provider.metaCls(driver, admin_driver)
        cls.metas[(driver.provider, driver.identity)] = meta
        return meta

    @classmethod
    def get_meta(cls, driver):
        id = (cls.provider, driver.identity)
        if cls.metas.get(id):
            return cls.metas[id]
        else:
            return cls.create_meta(driver)

    @classmethod
    def get_metas(cls):
        super_metas = {}
        map(super_metas.update, [AWSProvider.metaCls.metas,
                                 EucaProvider.metaCls.metas,
                                 OSProvider.metaCls.metas])
        return super_metas

    def test_links(self):
        return active_instances(self.driver.list_instances())

    def _split_creds(self, creds, default_key,
                     default_secret, default_tenant=None):
        key = creds.get('key', default_key)
        secret = creds.get('secret', default_secret)
        # Use the project or tenant name.
        tenant = creds.get('ex_project_name',
                           creds.get('ex_tenant_name', default_tenant))
        if tenant:
            return (key, secret, tenant)
        else:
            return (key, secret)

    def create_admin_driver(self, creds=None):
        raise NotImplementedError

    def all_instances(self):
        return self.provider.instanceCls.get_instances(
            self.admin_driver._connection.ex_list_all_instances(),
            self)

    def reset(self):
        Meta.reset()
        self.metas = {}

    @classmethod  # order matters... /sigh
    def reset(cls):
        cls.metas = {}

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return reduce(lambda x, y: x+y, map(unicode, [self.__class__,
                                                      " ",
                                                      self.json()]))

    def __repr__(self):
        return str(self)

    def json(self):
        return {'driver': self.driver,
                'identity': self.identity,
                'provider': self.provider.name}


class AWSMeta(Meta):

    provider = AWSProvider

    def create_admin_driver(self, creds=None):
        if not hasattr(settings, 'AWS_KEY'):
            return self.driver
        logger.debug(self.provider)
        logger.debug(type(self.provider))
        identity = AWSIdentity(self.provider,
                               settings.AWS_KEY,
                               settings.AWS_SECRET)
        driver = AWSDriver(self.provider, identity)
        return driver

    def all_instances(self):
        return self.admin_driver.list_instances()


class EucaMeta(Meta):

    provider = EucaProvider

    def create_admin_driver(self, creds=None):
        key, secret = self._split_creds(creds,
                                        settings.EUCA_ADMIN_KEY,
                                        settings.EUCA_ADMIN_SECRET)
        identity = EucaIdentity(self.provider, key, secret)
        driver = EucaDriver(self.provider, identity)
        return driver

    def occupancy(self):
        return self.admin_driver.list_sizes()

    def all_instances(self):
        return self.admin_driver.list_instances()


class OSMeta(Meta):

    provider = OSProvider

    def create_admin_driver(self, creds=None):
        """
        DEPRECATED
        """
        admin_provider = OSProvider()
        provider_creds = self.provider_options
        key, secret, tenant =\
            self._split_creds(creds,
                              '',
                              '',
                              '')
        admin_identity = OSIdentity(admin_provider,
                                    key,
                                    secret,
                                    ex_tenant_name=tenant)
        admin_driver = OSDriver(admin_provider,
                                admin_identity,
                                **provider_creds)
        return admin_driver

    def total_remaining(self, max_, total, used, size):
        """
        Given max, total used and size calculate and return a
        2-tuple with the (max, remaining).
        """
        if size != 0:
            return (floor(max_), floor((total - used) / size))
        else:
            return (floor(max_), sys.maxint)

    def _cpu_stats(self, size, cpu_total, cpu_used, cpu_overcommit):
        if cpu_overcommit > 0:
            cpu_used = cpu_used - cpu_overcommit
        # CPUs go by many different, provider-specific names..
        if hasattr(size._size, 'cpu'):
            cpu_count = size._size.cpu
        elif hasattr(size._size, 'vcpus'):
            cpu_count = size._size.vcpus
        else:
            logger.warn("Could not find a CPU value for size %s" % size)
            cpu_count = -1
        if cpu_count > 0:
            max_by_cpu = float(cpu_total)/float(size.cpu)
        else:
            # I don't know about this?
            max_by_cpu = sys.maxint
        return self.total_remaining(max_by_cpu, cpu_total,
                                    cpu_used, cpu_count)

    def _ram_stats(self, size, ram_total, ram_used, ram_overcommit):
        if ram_overcommit > 0:
            ram_used = ram_used - ram_overcommit
        if size._size.ram > 0:
            max_by_ram = float(ram_total) / float(size._size.ram)
        else:
            max_by_ram = sys.maxint
        return self.total_remaining(max_by_ram, ram_total, ram_used, size.ram)

    def _disk_stats(self, size, disk_total, disk_used, disk_overcommit):
        if disk_overcommit > 0:
            disk_used = disk_used - disk_overcommit
        if size._size.disk > 0:
            max_by_disk = float(disk_total) / float(size._size.disk)
        else:
            max_by_disk = sys.maxint
        return self.total_remaining(max_by_disk, disk_total,
                                    disk_used, size._size.disk)

    def _calculate_overcommits(self, sizes, remove_totals):
        instances = self.admin_driver.list_all_instances()
        size_map = {size.id:size for size in sizes}
        for instance in instances:
            if instance.extra['status'] in ['suspended','shutoff']:
                #oc == OverCommited
                oc_size = size_map.get(instance.size.id)
                if not oc_size:
                    logger.warn("Size %s NOT found in list of sizes. Cannot"
                                " remove instance %s from calculation"
                                % (instance.size.id, instance.id))
                    continue
                remove_totals['cpu'] = remove_totals['cpu'] + oc_size.cpu
                remove_totals['ram'] = remove_totals['ram'] + oc_size.ram
                remove_totals['disk'] = remove_totals['disk'] + oc_size.disk
        return remove_totals


    def _instance_capacity_on_node(self, size, node):
        pass

    def _instance_capacity_vcpus(self):
        pass

    def _sum_active_compute_nodes(self):
        acs = self._active_compute_nodes()
        return {"total_vcpus": sum([ac["vcpus"] for ac in acs]),
                "total_memory_mb": sum([ac["memory_mb"] for ac in acs]),
                "total_local_gb": sum(ac["local_gb"] for ac in acs)}

    def _active_compute_nodes(self):
        active_nodes = set(
            [self._scrub_hostname(n["host"])\
             for n in self.admin_driver._connection.ex_os_services()\
             if n["status"] == "enabled"])
        nodes = {}
        for n in self.admin_driver._connection.ex_detail_hypervisor_nodes():
            hostname = self._scrub_hostname(n["hypervisor_hostname"])
            if hostname in active_nodes:
                nodes[hostname] = n
        return nodes

    def _get_node(self, nodes, instance):
        hostname = instance\
            .extra["object"]\
            .get("OS-EXT-SRV-ATTR:hypervisor_hostname")
        if hostname:
            hostname = self._scrub_hostname(hostname)
        return nodes.get(hostname)

    def _get_size(self, sizes, instance):
        size_id = instance.size.id
        size = [s for s in sizes if s.id == size_id]
        if size and len(size) == 1:
            return size[0]
        else:
            return None

    def _scrub_hostname(self, hostname):
        if not hostname:
            return None
        url = urlparse.urlparse(hostname)
        if not url.hostname:
            return url.path.split(".")[0]
        else:
            return url.hostname.split(".")[0]

    def _get_hashable_node(self, node):
        if not node:
            return None
        return self._scrub_hostname(node["hypervisor_hostname"])

    def _add_occupancy(self, occupancy, node, size, instance):
        node_key = self._get_hashable_node(node)
        occ = occupancy.get(node_key)
        if not occ:
            occupancy[node_key] = {
                "cpu": 0,
                "mem": 0,
                "disk": 0,
                "instances": []
            }
            occ = occupancy[node_key]
        occ["cpu"] += size.cpu
        occ["mem"] += size.ram
        occ["disk"] += size.ephemeral
        occ["instances"].append(instance)

# for host, stats in rahr.items():
#         if not host:
#             continue
#         node = nodes[host]
#         max_cpu = node["vcpus"]
#         max_mem = node["memory_mb"]
#         print("host[{0}] cpu ratio({1}/{2}vcpus): {3:03.5f} memory ratio ({4}/{5}MB): {6:03.5f}".format(
#             host,
#             stats["cpu"],
#             max_cpu,
#             stats["cpu"]/(1.0*max_cpu),
#             stats["mem"],
#             max_mem,
#             stats["mem"]/(1.0*max_mem)))


    def new_occupancy(self, overcommited=True):
        """
        Calculate occupancy using an admin account.

        Get size, instance and compute node data then
        calculate a better occupancy than _ex_hypervisor_statistics.
        Our statistics only look at instance states that use resources
        on the compute node.
        """
        sizes = self.admin_driver.list_sizes()
        nodes = self._active_compute_nodes()
        occupancy = {}
        for i in self.all_instances():
            node = self._get_node(nodes, i)
            size = self._get_size(sizes, i)
            self._add_occupancy(occupancy, node, size, i)
        return occupancy

    def occupancy(self, overcommited=False):
        """
        Add Occupancy data to NodeSize.extra
        """
        occ = self.admin_driver._connection\
                               .ex_hypervisor_statistics()
        remove_totals = {
                'cpu':0,
                'ram':0,
                'disk':0
            }
        sizes = self.admin_driver.list_sizes()
        if not overcommited:
            self._calculate_overcommits(sizes, remove_totals)

        for size in sizes:
            total_cpu, remaining_cpu = self._cpu_stats(size,
                                                      occ['vcpus'],
                                                      occ['vcpus_used'],
                                                      remove_totals['cpu'])
        
            total_ram, remaining_ram = self._ram_stats(size,
                                                       occ['memory_mb'],
                                                       occ['memory_mb_used'],
                                                       remove_totals['ram'])
            total_disk, remaining_disk = self._disk_stats(size,
                                                         occ['local_gb'],
                                                         occ['local_gb_used'],
                                                         remove_totals['disk'])
            remaining = min(remaining_cpu,
                            remaining_ram,
                            remaining_disk)
            if remaining == remaining_cpu:
                total = total_cpu
            elif remaining == remaining_ram:
                total = total_ram
            else:
                total = total_disk
            size.extra['occupancy'] = {'total': total,
                                       'remaining': remaining}
        return sizes

    def add_metadata_deployed(self, machine):
        """
        Add {"deployed": "True"} key and value to the machine's metadata.
        """
        machine_metadata = self.admin_driver._connection\
                                            .ex_get_image_metadata(machine)
        machine_metadata["deployed"] = "True"
        self.admin_driver._connection\
                         .ex_set_image_metadata(machine, machine_metadata)

    def remove_metadata_deployed(self, machine):
        """
        Remove the {"deployed": "True"} key and value from the machine's
        metadata, if it exists.
        """
        machine_metadata = self.admin_driver._connection\
                                            .ex_get_image_metadata(machine)
        if machine_metadata.get("deployed"):
            self.admin_driver._connection.ex_delete_image_metadata(machine,
                                                                   "deployed")

    def stop_all_instances(self, destroy=False):
        """
        Stop all instances and delete tenant networks for all users.

        To destroy instances instead of stopping them use the destroy
        keyword (destroy=True).
        """
        for instance in self.all_instances():
            if destroy:
                self.admin_driver.destroy_instance(instance)
                logger.debug('Destroyed instance %s' % instance)
            else:
                if instance.get_status() == 'active':
                    self.admin_driver.stop_instance(instance)
                    logger.debug('Stopped instance %s' % instance)
        os_driver = OSAccountDriver()
        if destroy:
            for username in os_driver.list_usergroup_names():
                tenant_name = username
                os_driver.network_manager.delete_tenant_network(username,
                                                                tenant_name)
        return True

    def destroy_all_instances(self):
        """
        Destroy all instances and delete tenant networks for all users.
        """
        for instance in self.all_instances():
            self.admin_driver.destroy_instance(instance)
            logger.debug('Destroyed instance %s' % instance)
        os_driver = OSAccountDriver()
        for username in os_driver.list_usergroup_names():
            tenant_name = username
            os_driver.network_manager.delete_tenant_network(username,
                                                            tenant_name)
        return True

    def all_instances(self, **kwargs):
        return self.provider.instanceCls.get_instances(
            self.admin_driver._connection.ex_list_all_instances(**kwargs),
            self)

    def all_volumes(self):
        return self.provider.instanceCls.get_volumes(
            self.admin_driver._connection.ex_list_all_volumes())
