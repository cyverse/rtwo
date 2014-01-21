"""
Atmosphere service meta.

"""
import sys

from abc import ABCMeta

from threepio import logger

from rtwo import settings

from rtwo.provider import AWSProvider, EucaProvider, OSProvider,\
    OSValhallaProvider
from rtwo.identity import AWSIdentity, EucaIdentity, OSIdentity
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
            self.provider)

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
        admin_provider = OSProvider()
        provider_creds = self.provider_options
        key, secret, tenant =\
            self._split_creds(creds,
                              settings.OPENSTACK_ADMIN_KEY,
                              settings.OPENSTACK_ADMIN_SECRET,
                              settings.OPENSTACK_ADMIN_TENANT)
        admin_identity = OSIdentity(admin_provider,
                                    key,
                                    secret,
                                    ex_tenant_name=tenant)
        admin_driver = OSDriver(admin_provider,
                                admin_identity,
                                **provider_creds)
        return admin_driver

    def _get_max_cpu(self, esh_size, cpu_total):
        # CPUs go by many different, provider-specific names..
        if hasattr(esh_size._size, 'cpu'):
            cpu_count = esh_size._size.cpu
        elif hasattr(esh_size._size, 'vcpus'):
            cpu_count = esh_size._size.vcpus
        else:
            logger.warn("Could not find a CPU value for size %s" % esh_size)
            cpu_count = -1
        if cpu_count > 0:
            max_by_cpu = float(cpu_total)/float(esh_size.cpu) 
        else:
            max_by_cpu = sys.maxint
        return max_by_cpu

    def _get_max_ram(self, esh_size, ram_total):
        if esh_size._size.ram > 0:
            max_by_ram = float(ram_total) / float(esh_size._size.ram)
        else:
            max_by_ram = sys.maxint
        return max_by_ram

    def _get_max_disk(self, esh_size, disk_total):
        if esh_size._size.disk > 0:
            max_by_disk = float(disk_total) / float(esh_size._size.disk)
        else:
            max_by_disk = sys.maxint
        return max_by_disk

    def occupancy(self):
        """
        Add Occupancy data to NodeSize.extra
        """
        occupancy_data = self.admin_driver._connection\
                                          .ex_hypervisor_statistics()
        all_instances = self.all_instances()
        sizes = self.admin_driver.list_sizes()
        for size in sizes:
            max_by_cpu = self._get_max_cpu(size, occupancy_data['vcpus'])
            max_by_ram = self._get_max_ram(size, occupancy_data['memory_mb'])
            max_by_disk = self._get_max_disk(size, occupancy_data['local_gb'])

            limiting_value = int(min(
                max_by_cpu,
                max_by_ram,
                max_by_disk))
            num_running = len([i for i in all_instances
                               if i.extra['flavorId'] == size.id])
            if not 'occupancy' in size.extra:
                size.extra['occupancy'] = {}
            size.extra['occupancy']['total'] = limiting_value
            size.extra['occupancy']['remaining'] = limiting_value - num_running
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
            self.provider)

    def all_volumes(self):
        return self.provider.instanceCls.get_volumes(
            self.admin_driver._connection.ex_list_all_volumes())
