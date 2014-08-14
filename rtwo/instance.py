"""
Atmosphere service instance.

"""
from threepio import logger

from rtwo.provider import AWSProvider, EucaProvider, OSProvider
from rtwo.machine import Machine, MockMachine
from rtwo.size import Size, MockSize


class Instance(object):

    owner = None

    provider = None

    machine = None

    size = None

    def __init__(self, node, provider):
        self.owner = None # Should be defined per-provider
        self._node = node
        self.id = node.id
        self.alias = node.id
        self.name = node.name
        #TODO: Remove when we are sure no-one else is using 'the old way'
        self.image_id = node.extra.get('imageId')
        if not self.image_id:
            self.image_id = node.extra.get('image_id')
        self.extra = node.extra
        self.ip = self.get_public_ip()
        self.provider = provider
        if Machine.machines.get((self.provider.identifier, self.image_id)):
            self.machine = Machine.machines[(self.provider.identifier,
                                             self.image_id)]

    @classmethod
    def get_instances(cls, nodes, provider):
        return [cls.provider.instanceCls(node, provider) for node in nodes]

    def get_public_ip(self):
        raise NotImplementedError()

    def get_status(self):
        raise NotImplementedError()

    def load(self):
        raise NotImplementedError()

    def save(self):
        raise NotImplementedError()

    def delete(self):
        raise NotImplementedError()

    def reset(self):
        self._node = None

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return reduce(
            lambda x, y: x+y,
            map(unicode, [self.__class__, " ", self.json()]))

    def __repr__(self):
        return str(self)

    def json(self):
        size_str = None
        machine_str = None
        if not self.size:
            size_str = "None"
        elif type(self.size) == str:
            size_str = self.size
        else:
            size_str = self.size.json()
        if not self.machine:
            machine_str = "None"
        elif type(self.machine) == str:
            machine_str = self.machine
        else:
            machine_str = self.machine.json()

        return {'id': self.id,
                'alias': self.alias,
                'name': self.name,
                'ip': self.ip,
                'provider': self.provider.name,
                'size': size_str,
                'machine': machine_str
            }


class AWSInstance(Instance):

    provider = AWSProvider

    def __init__(self, node, provider):
        Instance.__init__(self, node, provider)
        self.owner = node.extra.get('ownerId')
        self.size = node.extra.get('instance_type')
        if not self.size:
            self.size = node.extra['instancetype']
        if Size.sizes.get((provider.identifier, self.size)):
            self.size = Size.sizes[(provider.identifier, self.size)]

    def get_public_ip(self):
        if self.extra \
           and self.extra.get('dns_name'):
            return self.extra['dns_name']


class EucaInstance(AWSInstance):

    provider = EucaProvider

    def get_public_ip(self):
        if self.extra:
            return self.extra.get('dns_name')

    def get_status(self):
        """
        """
        status = "Unknown"
        if self.extra \
           and self.extra.get('status'):
            status = self.extra['status']
        return status


class OSInstance(Instance):

    provider = OSProvider

    def __init__(self, node, provider):
        Instance.__init__(self, node, provider)

        #Unfortunately we can't get the tenant_name..
        self.owner = node.extra.get('tenantId')

        if not self.machine:
            # Attempt to do a cache lookup first!
            self.machine = self.provider.machineCls.lookup_cached_machine(
                node.extra['imageId'], self.provider.identifier)
        if not self.machine:
            self.machine = MockMachine(node.extra['imageId'], self.provider)
        if not self.size:
            self.size = self.provider.sizeCls.lookup_size(
                node.extra['flavorId'], provider)
        if not self.size:
            self.size = MockSize(node.extra['flavorId'],
                                       self.provider)

    def _get_flavor_for_instance(self, node):
        try:
            flavor = node.driver.ex_get_size(node.extra['flavorId'])
            # Add size to cache
            self.size = self.provider.sizeCls.create_size(
                self.provider, flavor)
            return self.size
        except Exception, no_flavor_found:
            self.size = MockSize(node.extra['flavorId'], self.provider)
            logger.exception("Instance %s is using a size %s"
                             "that has been deleted."
                             % (node.id, node.extra['flavorId']))
            return None

    def _get_image_for_instance(self, node):
        try:
            # Image not in cache, try and add it
            image = node.driver.ex_get_image(node.extra['imageId'])
            self.machine = self.provider.machineCls.create_machine(
                self.provider, image, self.provider.identifier)
            return self.machine
        except Exception, no_image_found:
            logger.exception("Instance %s is using an image %s that has been "
                        "deleted." % (node.id, node.extra['imageId']))
            self.machine = MockMachine(node.extra['imageId'], self.provider)
            return self.machine
    def get_status(self):
        """
        TODO: If openstack: Use extra['task'] and extra['power']
        to determine the appropriate status.
        """
        status = "Unknown"
        if self.extra \
           and self.extra.get('status'):
            status = self.extra['status']
            task = self.extra.get('task')
            if task:
                status += ' - %s' % self.extra['task']
            extra_status = self.extra.get('metadata', {}).get('tmp_status')
            if extra_status and not task and status == 'active':
                status += ' - %s' % extra_status

        return status

    def get_public_ip(self):
        if hasattr(self, "ip"):
            return self.ip
        if self._node and self._node.public_ips:
            return self._node.public_ips[0]
