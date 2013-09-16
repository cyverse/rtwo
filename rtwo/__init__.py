""" rtwo

"""
try:
    import libcloud.security
    libcloud.security.VERIFY_SSL_CERT = False
    libcloud.security.VERIFY_SSL_CERT_STRICT = False

    from . import settings
    from . import driver
    from . import identity
    from . import provider
    from . import meta
    #TODO: Migrating back to atmosphere
    #from .compute import initialize
    #initialize()
except ImportError:
    #This is normal on first-install..
    pass
