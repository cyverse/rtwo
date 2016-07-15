"""
Atmosphere service machine.

"""
from abc import ABCMeta

from rtwo.models.provider import AWSProvider, EucaProvider, OSProvider

from threepio import logger

class BaseMachine(object):
    __metaclass__ = ABCMeta


class MockMachine(BaseMachine):

    def __init__(self, image_id, provider):
        self.id = image_id
        self.alias = image_id
        self.name = 'Unknown image %s' % image_id
        self._image = None
        self.provider = provider

    def json(self):
        return {'id': self.id,
                'alias': self.alias,
                'name': self.name,
                'provider': self.provider.name}


class Machine(BaseMachine):

    provider = None

    machines = {}

    lc_images = None

    def __init__(self, lc_image):
        self._image = lc_image
        self.id = lc_image.id
        self.alias = lc_image.id
        self.name = lc_image.name

    @classmethod
    def create_machine(cls, provider, lc_image, identifier):
        machine = provider.machineCls(lc_image)
        cls.add_to_cache(provider, machine, identifier)
        return machine

    @classmethod
    def invalidate_provider_cache(cls, provider):
        cls.machines[provider.identifier] = {}

    @classmethod
    def invalidate_machine_cache(cls, provider, machine):
        """
        DO NOT USE THIS METHOD
        Removing a machine from the cache will have no affect on calls to
        driver.list_machines(), to clear the cache you must use
        invalidate_provider_cache
        """
        return cls.invalidate_provider_cache(provider)
        alias = machine.id
        provider_cache = cls.machines.get(provider.identifier, {})
        provider_cache[alias] = None
        cls.machines[provider.identifier] = provider_cache

    @classmethod
    def add_to_cache(cls, provider, machine, identifier):
        alias = machine.id
        machine_dict = cls.machines.get(identifier, {})
        machine_dict[alias] = machine
        cls.machines[identifier] = machine_dict

    @classmethod
    def lookup_cached_machine(cls, alias, identifier):
        provider_machines = cls.machines.get(identifier)
        if not provider_machines:
            #logger.info("Created new machine dict for provider %s" % identifier)
            provider_machines = {}
        machine = provider_machines.get(alias)
        if machine:
            #logger.info("Found machine for provider:%s - %s" %
            #    (identifier, machine))
            return machine
        return None

    @classmethod
    def get_cached_machine(cls, lc_image, identifier):
        alias = lc_image.id
        provider_machines = cls.machines.get(identifier)
        if not provider_machines:
            #logger.info("Created new machine dict for provider %s" % identifier)
            provider_machines = {}
        machine = provider_machines.get(alias)
        if machine:
            #logger.info("Found machine for provider:%s - %s" %
            #    (identifier, machine))
            return machine
        return cls.create_machine(cls.provider, lc_image, identifier)

    @classmethod
    def get_cached_machines(cls, identifier, lc_list_images_method, *args, **kwargs):
        """
        Identifier - Used to identify the specific provider being used:
        ex: "iPlant Eucalyptus", "Openstack 1", "Openstack 2"
        If using only one provider, this variable can be set to any value.
        """
        provider_machines = cls.machines.get(identifier)
        if not provider_machines:
            logger.debug("Cache miss for identifier - %s" % identifier)
        if not provider_machines or not cls.lc_images:
            #Add new provider to the cache
            cls.lc_images = lc_list_images_method(*args, **kwargs)
            logger.debug("Caching %s machines for identifier:%s" %
                         (len(cls.lc_images), identifier))
        return [cls.get_cached_machine(lc_image, identifier) for lc_image in cls.lc_images]

    def reset(self):
        Machine.reset()
        self.machines = {}
        self.lc_images = None

    @classmethod  # order matters... /sigh
    def reset(cls):
        cls.machines = {}
        cls.lc_images = None

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return reduce(
            lambda x, y: x+y,
            map(unicode, [self.__class__, " ", self.json()])
        )

    def __repr__(self):
        return str(self)

    def json(self):
        return {'id': self.id,
                'alias': self.alias,
                'name': self.name,
                'provider': self.provider.name}


class AWSMachine(Machine):

    provider = AWSProvider


class EucaMachine(Machine):

    provider = EucaProvider


class OSMachine(Machine):

    provider = OSProvider
