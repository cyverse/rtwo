"""
Atmosphere service volume.

"""
from abc import ABCMeta

from threepio import logger

from rtwo.models.provider import AWSProvider, EucaProvider, OSProvider


class BaseVolume(object):
    __metaclass__ = ABCMeta


class MockVolume(BaseVolume):

    def __init__(self, volume_id, provider):
        self._volume = None
        self.id = volume_id
        self.alias = volume_id
        self.size = -1
        self.attachment_set = []
        self.extra = {}
        self.name = "Mock Volume %s" % volume_id
        self.provider = provider


class Volume(BaseVolume):

    provider = None

    machine = None

    def __init__(self, lc_volume):
        self._volume = lc_volume
        self.id = lc_volume.id
        self.alias = lc_volume.id
        self.attachment_set = lc_volume.extra['attachments']
        self.extra = lc_volume.extra
        self.name = lc_volume.name
        self.provider = self.provider
        self.size = lc_volume.size

    @classmethod
    def get_volumes(cls, volumes):
        return map(cls.provider.volumeCls, volumes)

    # order matters with reset methods.
    def reset(self):
        Volume.reset()
        self._volume = None
        self.machine = None

    # again order matters... /sigh
    @classmethod
    def reset(cls):
        cls._volume = None
        cls.machine = None

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return reduce(lambda x, y: x+y,
                      map(unicode, [self.__class__, " ", self.json()]))

    def __repr__(self):
        return str(self)

    def json(self):
        return {'id': self.id,
                'alias': self.alias,
                'attachment_set': self.attachment_set,
                'extra': self.extra,
                'name': self.name,
                'provider': self.provider.name,
                'size': self.size}


class AWSVolume(Volume):

    provider = AWSProvider


class EucaVolume(Volume):

    provider = EucaProvider


class OSVolume(Volume):

    provider = OSProvider
