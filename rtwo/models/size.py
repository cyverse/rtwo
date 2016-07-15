"""
Atmosphere service size.

"""
from abc import ABCMeta

from rtwo.models.provider import AWSProvider, EucaProvider, OSProvider
from threepio import logger


class BaseSize(object):
    __metaclass__ = ABCMeta


class Size(BaseSize):

    provider = None

    sizes = {}

    lc_sizes = None

    def __init__(self, lc_size):
        self._size = lc_size
        self.id = self._size.id
        self.name = self._size.name
        self.price = self._size.price
        self.ram = self._size.ram
        self.disk = self._size.disk
        if hasattr(self._size, 'extra'):
            self.extra = self._size.extra
        else:
            self.extra = {}  # Placeholder Dict
        self.cpu = self.extra.get('cpu',0)
        self.ephemeral = self.extra.get('ephemeral',0)
        self.bandwidth = 0

    @classmethod
    def create_size(cls, provider, lc_size):
        size = provider.sizeCls(lc_size)
        alias = size.id
        cls.sizes[(provider.identifier, alias)] = size
        return size

    @classmethod
    def lookup_size(cls, alias, provider):
        if cls.sizes.get((provider.identifier, alias)):
            return cls.sizes[
                (provider.identifier, alias)
            ]
        else:
            return None

    @classmethod
    def get_size(cls, lc_size, provider):
        alias = lc_size.id
        if cls.sizes.get((provider.identifier, alias)):
            return cls.sizes[
                (provider.identifier, alias)
            ]
        else:
            return cls.create_size(provider, lc_size)

    @classmethod
    def get_sizes(cls, provider, lc_list_sizes_method):
        identifier = provider.identifier
        cached_sizes = cls.sizes.get(identifier)
        if not cached_sizes or not cls.lc_sizes:
            cls.lc_sizes = lc_list_sizes_method()
            logger.debug("Caching %s sizes for identifier:%s" %
                         (len(cls.lc_sizes), identifier))
        return sorted(
            [cls.get_size(size, provider) for size in cls.lc_sizes],
            key=lambda s: (s.cpu, s.ram))

    def reset(self):
        Size.reset()
        self._size = None
        self.lc_sizes = None
        self.sizes = {}

    @classmethod
    def reset(cls):
        cls.lc_sizes = None
        cls.sizes = {}

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return reduce(
            lambda x, y: x+y,
            map(unicode, [self.__class__, " ", self.json()]))

    def __repr__(self):
        return str(self)

    def json(self):
        return {
            'id': self.name,
            'provider': self.provider.identifier,
            'alias': self.id,
            'name': self.name,
            'cpu': self.cpu,
            'ram': self.ram,
            'root': self.disk,
            'disk': self.ephemeral,
            'bandwidth': self.bandwidth,
            'price': self.price}

class MockSize(Size):
    def __init__(self, size_id, provider):
        self.provider = provider
        self._size = None
        self.name = "Unknown Size %s" % size_id
        self.alias = size_id
        self.id = size_id
        self.price = None
        self.ram = 0
        self.disk = 0
        self.extra = {}  # Placeholder Dict
        self.cpu = 0
        self.ephemeral = 0

    def json(self):
        return {
            'id': self.id,
            'provider': self.provider.identifier,
            'alias': self.id,
            'name': 'MockSize %s' % self.id,
            'cpu': self.cpu,
            'ram': '',
            'root': '',
            'disk': '',
            'bandwidth': '',
            'price': ''}

class EucaSize(Size):

    provider = EucaProvider


class AWSSize(Size):

    provider = AWSProvider


class OSSize(Size):

    provider = OSProvider
