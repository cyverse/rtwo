"""
Atmosphere service exceptions.

"""
from neutronclient.common.exceptions import NeutronClientException, NotFound as NeutronNotFound, BadRequest as NeutronBadRequest
from keystoneclient.apiclient.exceptions import Unauthorized as KeystoneUnauthorized


class NonZeroDeploymentException(Exception):
    pass


class ServiceException(Exception):
    pass


class ConnectionFailure(ServiceException):
    pass

class MissingArgsException(ServiceException):
    pass
