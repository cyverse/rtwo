"""
Atmosphere service compute.
"""
from threepio import logger

from rtwo import settings

from rtwo.provider import AWSProvider, EucaProvider, OSProvider
from rtwo.driver import EucaDriver, AWSDriver

from libcloud.common.types import InvalidCredsError

def _initialize_provider(provider, driverCls, **kwargs):
    try:
        identity = provider.identityCls(provider, **kwargs)
        driver = driverCls(provider, identity)
        machs = driver.list_machines()
        driver.list_sizes()
    except InvalidCredsError:
        logger.warn("Credentials are incorrect for provider %s, identity %s"
                % (provider, identity))
    except Exception as e:
        logger.exception(e)


def _initialize_aws():
    if hasattr(settings, 'AWS_KEY') \
       and hasattr(settings, 'AWS_SECRET'):
        _initialize_provider(AWSProvider(),
                             AWSDriver,
                             key=settings.AWS_KEY,
                             secret=settings.AWS_SECRET,
                             user="admin")


def _initialize_euca():
    if hasattr(settings, 'EUCA_ADMIN_KEY') \
       and hasattr(settings, 'EUCA_ADMIN_SECRET'):
        _initialize_provider(EucaProvider(),
                             EucaDriver,
                             key=settings.EUCA_ADMIN_KEY,
                             secret=settings.EUCA_ADMIN_SECRET,
                             user="admin")


def initialize():
    """
    Initialize machines and sizes using an admin identity.

    NOTE: This is required to ensure Eucalyptus and AWS have valid information
    for sizes and machines.
    """
    _initialize_euca()
    _initialize_aws()

EucaProvider.set_meta()
AWSProvider.set_meta()
OSProvider.set_meta()
initialize()
