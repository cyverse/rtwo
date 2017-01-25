"""
Atmosphere service identity.

"""
from abc import ABCMeta, abstractmethod

from threepio import logger

from rtwo.exceptions import MissingArgsException
from rtwo.models.provider import AWSProvider, EucaProvider, OSProvider, MockProvider


class BaseIdentity(object):
    __metaclass__ = ABCMeta

    provider = None

    groups = []
    providers = []
    machines = []
    instances = []

    credentials = {}

    @abstractmethod
    def __init__(self, provider, user, key, secret):
        raise NotImplemented


class Identity(BaseIdentity):

    def __init__(self, provider, key=None, secret=None, user=None, **kwargs):
        if issubclass(type(provider), self.provider):
            self.providers.append(provider)
        else:
            logger.warn("Provider doesn't match (%s != %s)." %
                        (provider, self.provider))
        self.user = user
        self.credentials = {}
        self.credentials.update(kwargs)
        self.credentials.update({'key': key, 'secret': secret})

    def get_username(self):
        return self.credentials['key']
    def get_groupname(self):
        return self.credentials['key']
    def __repr__(self):
        return '%s (%s) Credentials: %s' % (self.__class__,
                                            self.credentials.get('key',''),
                                            self.credentials.keys())



class AWSIdentity(Identity):

    provider = AWSProvider


class EucaIdentity(Identity):

    provider = EucaProvider


class OSIdentity(Identity):

    provider = OSProvider

class MockIdentity(Identity):

    provider = MockProvider
