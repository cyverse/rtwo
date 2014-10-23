"""
Atmosphere service compute.
"""
from threepio import logger

from rtwo import settings

from rtwo.provider import AWSProvider, EucaProvider, OSProvider
from rtwo.driver import EucaDriver, AWSDriver

from libcloud.common.types import InvalidCredsError


EucaProvider.set_meta()
AWSProvider.set_meta()
OSProvider.set_meta()

