"""
Atmosphere service exceptions.

"""


class NonZeroDeploymentException(Exception):
    pass


class ServiceException(Exception):
    pass


class MissingArgsException(ServiceException):
    pass
