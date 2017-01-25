"""
Atmosphere service provider.

"""
from abc import ABCMeta, abstractmethod

from libcloud.compute.types import Provider as LProvider

from threepio import logger

from rtwo.drivers.openstack_facade import OpenStack_Esh_NodeDriver
from rtwo.drivers.eucalyptus import Eucalyptus_Esh_NodeDriver
from rtwo.drivers.aws import Esh_EC2NodeDriver

from rtwo.exceptions import ServiceException


def lc_provider_id(provider):
    """
    Get the libcloud Provider using our service provider.

    Return the libcloud.compute Provider value.
    """
    p = None
    try:
        p = LProvider.__dict__[provider.location]
    except Exception as e:
        logger.warn("Unable to find provider location: %s." %
                    provider.location)
        raise ServiceException(e)
    return p


class BaseProvider(object):
    __metaclass__ = ABCMeta

    identity = None

    lc_driver = None

    options = {}

    #Used to support multi-cloud
    identifier = ''

    location = ''

    name = ''

    identityCls = None

    instanceCls = None

    machineCls = None

    sizeCls = None

    @abstractmethod
    def __init__(self, *args, **kwargs):
        raise NotImplemented

    @abstractmethod
    def provider_id(self):
        raise NotImplemented

    @abstractmethod
    def set_options(self):
        raise NotImplemented

    @abstractmethod
    def get_driver(self, *args, **kwargs):
        raise NotImplemented

    def __repr__(self):
        return '%s (%s)' % (self.__class__, self.identifier)


class Provider(BaseProvider):

    def __init__(self, url=None, identifier=None):
        """
        :param url: url to use for this provider.
        """
        if url:
            self.options.update(Provider.parse_url(kwargs['url']))
        if not identifier:
            identifier = self.location
        self.identifier = identifier

    def set_options(self, provider_credentials):
        """
        Get provider specific options.

        Return provider specific options in a dict.
        """
        self.options = {}
        self.options.update(provider_credentials)
        self.options.update(self.identity.credentials)
        return self.options

    @classmethod
    def parse_url(cls, url):
        """
        Parse the url into the options dictionary.
        """
        from urlparse import urlparse
        urlobj = urlparse(url)
        options = {}
        options['host'] = urlobj.hostname
        options['port'] = urlobj.port
        options['path'] = urlobj.path
        options['secure'] = urlobj.scheme == 'https'
        return options

    def provider_id(self):
        try:
            return lc_provider_id(self)
        except Exception as e:
            raise ServiceException(e)


class AWSProvider(Provider):

    name = 'Amazon EC2'

    location = 'EC2_US_EAST'

    @classmethod
    def set_meta(cls):
        from rtwo.models.identity import AWSIdentity
        from rtwo.models.machine import AWSMachine
        from rtwo.models.instance import AWSInstance
        from rtwo.models.size import AWSSize
        from rtwo.models.volume import AWSVolume
        from rtwo.meta import AWSMeta
        cls.identityCls = AWSIdentity
        cls.machineCls = AWSMachine
        cls.instanceCls = AWSInstance
        cls.sizeCls = AWSSize
        cls.volumeCls = AWSVolume
        cls.metaCls = AWSMeta

    def set_options(self, provider_credentials):
        """
        Get provider specific options.

        Return provider specific options in a dict.
        """
        self.options = {}
        self.options.update(provider_credentials)
        self.options.update(self.identity.credentials)
        return self.options

    def get_driver(self, identity, **provider_credentials):
        """
        Get the libcloud driver using our service identity.

        Return the libcloud.compute driver class.
        """
        self.identity = identity
        self.lc_driver = Esh_EC2NodeDriver
        self.set_options(provider_credentials)
        return self.lc_driver(key=self.options['key'],
                              secret=self.options['secret'])


class AWSUSWestProvider(AWSProvider):

    location = 'EC2_US_WEST'


class AWSUSEastProvider(AWSProvider):

    location = 'EC2_US_EAST'


class EucaProvider(Provider):

    name = 'Eucalyptus'

    # This need to be in all caps to match lib cloud.
    location = 'EUCALYPTUS'

    @classmethod
    def set_meta(cls):
        from rtwo.models.identity import EucaIdentity
        from rtwo.models.machine import EucaMachine
        from rtwo.models.instance import EucaInstance
        from rtwo.models.size import EucaSize
        from rtwo.models.volume import EucaVolume
        from rtwo.meta import EucaMeta
        cls.identityCls = EucaIdentity
        cls.machineCls = EucaMachine
        cls.instanceCls = EucaInstance
        cls.sizeCls = EucaSize
        cls.volumeCls = EucaVolume
        cls.metaCls = EucaMeta

    def set_options(self, provider_credentials):
        """
        Get provider specific credentials.

        Return any provider specific credentials in a dict.
        """
        self.options = {'host': '128.196.172.136',
                        'secure': False,
                        'port': 8773,
                        'path': '/services/Eucalyptus'}
        # Options default to provider
        self.options.update(provider_credentials)
        self.options.update(self.identity.credentials)
        return self.options

    def get_driver(self, identity, **provider_credentials):
        """
        Get the libcloud driver using our service identity.

        Return the libcloud.compute driver class.
        """
        self.lc_driver = Eucalyptus_Esh_NodeDriver

        self.identity = identity
        self.set_options(provider_credentials)

        return self.lc_driver(key=self.options['key'],
                              secret=self.options['secret'],
                              secure=self.options['secure'] != False,
                              host=self.options['host'],
                              port=self.options['port'],
                              path=self.options['path'])


class MockProvider(Provider):
    name = 'Mock'
    location = 'MOCK'
    def set_options(self, provider_credentials):
        """
        Get provider specific options.

        Return provider specific options in a dict.
        """
        self.options = {'secure': 'False',
                        'ex_force_auth_version': '2.0_password',
                        'ex_domain_name': None,
                        'ex_force_auth_url': None,
                        'ex_force_base_url': None,
                        'ex_force_auth_token': None
                       }
        return self.options

    def get_driver(self, identity, **provider_credentials):
        """
        Get the libcloud driver using our service identity.

        Return the libcloud.compute driver class.
        """
        self.set_options(provider_credentials)
        return None

class OSProvider(Provider):

    name = 'OpenStack'

    location = 'OPENSTACK'

    @classmethod
    def set_meta(cls):
        from rtwo.models.identity import OSIdentity
        from rtwo.models.machine import OSMachine
        from rtwo.models.instance import OSInstance
        from rtwo.models.size import OSSize
        from rtwo.models.volume import OSVolume
        from rtwo.meta import OSMeta
        cls.identityCls = OSIdentity
        cls.machineCls = OSMachine
        cls.instanceCls = OSInstance
        cls.sizeCls = OSSize
        cls.volumeCls = OSVolume
        cls.metaCls = OSMeta

    def set_options(self, provider_credentials):
        """
        Get provider specific options.

        Return provider specific options in a dict.
        """
        self.options = {'secure': 'False',
                        'ex_force_auth_version': '2.0_password',
                        'ex_domain_name': None,
                        'ex_force_auth_url': None,
                        'ex_force_base_url': None,
                        'ex_force_auth_token': None
                       }
        self.options.update(provider_credentials)
        self.options.update(self.identity.credentials)
        #Basic validation to avoid 'hard-to-reason-about-errors'
        if self.options['ex_force_auth_version'] == '2.0_password' and 'tokens' not in self.options['ex_force_auth_url']:
           raise ValueError("Conflicting options -- If you are using '2.0_password' for Keystone Authentication, your auth_url should include '/v2.0/tokens' in addition to the http(s)://hostname:port")
        elif self.options['ex_force_auth_version'] == '3.x_password' and 'tokens' in self.options['ex_force_auth_url']:
           raise ValueError("Conflicting options -- If you are using '3.x_password' for Keystone Authentication, your auth_url should NOT include '/v2.0/tokens'. Instead use: http(s)://hostname:port")

        return self.options

    def get_driver(self, identity, **provider_credentials):
        """
        Get the libcloud driver using our service identity.

        Return the libcloud.compute driver class.
        """
        self.identity = identity
        self.lc_driver = OpenStack_Esh_NodeDriver
        self.set_options(provider_credentials)
        return self.lc_driver(
            key=self.options['key'],
            secret=self.options['secret'],
            secure=self.options['secure'] != 'False',
            ex_domain_name=self.options['ex_domain_name'],
            ex_force_base_url=self.options['ex_force_base_url'],
            ex_force_auth_url=self.options['ex_force_auth_url'],
            ex_force_auth_version=self.options['ex_force_auth_version'],
            ex_force_auth_token=self.options['ex_force_auth_token'],
            ex_tenant_name=self.options['ex_tenant_name'])


class OSValhallaProvider(OSProvider):

    region_name = "ValhallaRegion"

    def set_options(self, provider_credentials):
        """
        """
        super(OSValhallaProvider, self).set_options(provider_credentials)


class OSMidgardProvider(OSProvider):

    region_name = "MidgardRegion"

    def set_options(self, provider_credentials):
        """
        """
        super(OSMidgardProvider, self).set_options(provider_credentials)
