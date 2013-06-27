"""
Atmosphere service exceptions.

"""


class ServiceException(Exception):
    pass


class MissingArgsException(ServiceException):
    pass
