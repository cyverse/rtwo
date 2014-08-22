"""
Atmosphere service exceptions.

"""


class NonZeroDeploymentException(Exception):
    pass


class ServiceException(Exception):
    pass


class ConnectionFailure(ServiceException):
    pass

class MissingArgsException(ServiceException):
    pass
