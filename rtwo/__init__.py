try:
    import libcloud.security
    libcloud.security.VERIFY_SSL_CERT = False
    libcloud.security.VERIFY_SSL_CERT_STRICT = False
except ImportError:
    pass
