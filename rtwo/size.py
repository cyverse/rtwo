"""
Atmosphere service size.

"""
from abc import ABCMeta

from rtwo.provider import AWSProvider, EucaProvider, OSProvider


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
        if hasattr(self._size, 'extra'):
            self.extra = self._size.extra
        else:
            self.extra = {}  # Placeholder Dict
        self.cpu = self.extra.get('cpu',0)
        self.ephemeral = self.extra.get('ephemeral',0)

    @classmethod
    def create_size(cls, provider, lc_size):
        size = provider.sizeCls(lc_size)
        alias = size.id
        cls.sizes[(provider, alias)] = size
        return size

    @classmethod
    def get_size(cls, lc_size, provider_identifier):
        alias = lc_size.id
        if cls.sizes.get((provider_identifier, alias)):
            return cls.sizes[
                (provider_identifier, alias)
            ]
        else:
            return cls.create_size(provider_identifier, lc_size)

    @classmethod
    def get_sizes(cls, provider_identifier, lc_list_sizes_method):
        if not cls.sizes or not cls.lc_sizes:
            cls.lc_sizes = lc_list_sizes_method()
        return sorted(
            [cls.get_size(size, provider_identifier) for size in cls.lc_sizes],
            key=lambda s: (s._size.ram, s._size.cpu))

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
            'id': self._size.name,
            'alias': self._size.id,
            'name': self._size.name,
            'cpu': self.cpu,
            'ram': self._size.ram,
            'disk': self._size.disk,
            'bandwidth': self._size.bandwidth,
            'price': self._size.price}


class EucaSize(Size):

    provider = EucaProvider


class AWSSize(Size):

    provider = AWSProvider


class OSSize(Size):

    provider = OSProvider
