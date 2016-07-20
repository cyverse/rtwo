"""
Atmosphere service exceptions.

"""
from neutronclient.common.exceptions import NeutronClientException, NotFound as NeutronNotFound, BadRequest as NeutronBadRequest, OverLimit as NeutronOverLimit, NeutronException
from keystoneclient.apiclient.exceptions import Unauthorized as KeystoneUnauthorized
from glanceclient.exc import HTTPConflict as GlanceConflict, HTTPForbidden as GlanceForbidden
from libcloud.common.types import InvalidCredsError as LibcloudInvalidCredsError, MalformedResponseError as LibcloudBadResponseError
from libcloud.compute.types import DeploymentError as LibcloudDeploymentError


class NonZeroDeploymentException(Exception):
    pass


class ServiceException(Exception):
    pass


class ConnectionFailure(ServiceException):
    pass

class MissingArgsException(ServiceException):
    pass
