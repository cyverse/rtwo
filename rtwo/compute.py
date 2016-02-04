"""
Atmosphere service compute.
"""
from threepio import logger

from rtwo import settings

from rtwo.provider import AWSProvider, EucaProvider, OSProvider
from rtwo.driver import EucaDriver, AWSDriver

from libcloud.common.types import InvalidCredsError


OSProvider.set_meta()

