"""
Atmosphere service exceptions.

"""
from neutronclient.common.exceptions import NeutronClientException, NotFound as NeutronNotFound, BadRequest as NeutronBadRequest, NeutronException
from novaclient.exceptions import OverLimit as NovaOverLimit
try:
    from keystoneclient.exceptions import Unauthorized as KeystoneUnauthorized
except ImportError:
    from keystoneclient.apiclient.exceptions import Unauthorized as KeystoneUnauthorized

from glanceclient.exc import HTTPConflict as GlanceConflict, HTTPForbidden as GlanceForbidden, ClientException as GlanceClientException
from libcloud.common.types import InvalidCredsError as LibcloudInvalidCredsError, MalformedResponseError as LibcloudBadResponseError
from libcloud.compute.types import DeploymentError as LibcloudDeploymentError
from libcloud.common.exceptions import BaseHTTPError  as LibcloudHTTPError


class NonZeroDeploymentException(Exception):
    pass


class ServiceException(Exception):
    pass


class ConnectionFailure(ServiceException):
    pass

class MissingArgsException(ServiceException):
    pass
