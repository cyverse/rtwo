""" rtwo.settings

    Try to find usable settings. First try to use atmosphere's secrets,
    if installed. Otherwise try to use test_settings.
"""
import threepio
if not threepio.logger:
    threepio.initialize("rtwo")
from threepio import logger

try:
    # Attempt initialization from atmosphere (Using secrets)
    from atmosphere.settings import secrets as settings
    dir(settings)  # Force it to fail.
except:
    settings = None
    try:
        from rtwo import local_settings as settings
        dir(settings)  # Force it to fail.
    except:
        try:
            from rtwo import test_settings as settings
            dir(settings)  # Force it to fail.
        except:
            settings = None


if not settings:
    class Settings(object):
        pass
    settings = Settings()
    settings.OPENSTACK_ADMIN_KEY = ""
    settings.OPENSTACK_ADMIN_SECRET = ""
    settings.OPENSTACK_AUTH_URL = ""
    settings.OPENSTACK_ADMIN_URL = ""
    settings.OPENSTACK_ADMIN_TENANT = ""
    settings.OPENSTACK_DEFAULT_REGION = ""
    settings.OPENSTACK_DEFAULT_ROUTER = ""
    settings.EUCA_ADMIN_KEY = ""
    settings.EUCA_ADMIN_SECRET = ""
    settings.SERVER_URL = ""
    settings.INSTANCE_SERVICE_URL = ""
    settings.ATMOSPHERE_VNC_LICENSE = ""


def set_settings(settings):
    global OPENSTACK_ADMIN_KEY, OPENSTACK_ADMIN_SECRET,\
        OPENSTACK_AUTH_URL, OPENSTACK_ADMIN_URL,\
        OPENSTACK_ADMIN_TENANT, OPENSTACK_DEFAULT_REGION,\
        OPENSTACK_DEFAULT_ROUTER, EUCA_ADMIN_KEY,\
        EUCA_ADMIN_SECRET, SERVER_URL,\
        INSTANCE_SERVICE_URL, ATMOSPHERE_VNC_LICENSE
    OPENSTACK_ADMIN_KEY = settings.OPENSTACK_ADMIN_KEY
    OPENSTACK_ADMIN_SECRET = settings.OPENSTACK_ADMIN_SECRET
    OPENSTACK_AUTH_URL = settings.OPENSTACK_AUTH_URL
    OPENSTACK_ADMIN_URL = settings.OPENSTACK_ADMIN_URL
    OPENSTACK_ADMIN_TENANT = settings.OPENSTACK_ADMIN_TENANT
    OPENSTACK_DEFAULT_REGION = settings.OPENSTACK_DEFAULT_REGION
    OPENSTACK_DEFAULT_ROUTER = settings.OPENSTACK_DEFAULT_ROUTER
    EUCA_ADMIN_KEY = settings.EUCA_ADMIN_KEY
    EUCA_ADMIN_SECRET = settings.EUCA_ADMIN_SECRET
    SERVER_URL = settings.SERVER_URL
    INSTANCE_SERVICE_URL = settings.INSTANCE_SERVICE_URL
    ATMOSPHERE_VNC_LICENSE = settings.ATMOSPHERE_VNC_LICENSE

set_settings(settings)

OPENSTACK_ARGS = {
    'username': OPENSTACK_ADMIN_KEY,
    'password': OPENSTACK_ADMIN_SECRET,
    'tenant_name': OPENSTACK_ADMIN_TENANT,
    'auth_url': OPENSTACK_ADMIN_URL,
    'region_name': OPENSTACK_DEFAULT_REGION
}

OPENSTACK_NETWORK_ARGS = {
    'auth_url': OPENSTACK_ADMIN_URL,
    'region_name': OPENSTACK_DEFAULT_REGION,
    'router_name': OPENSTACK_DEFAULT_ROUTER
}
